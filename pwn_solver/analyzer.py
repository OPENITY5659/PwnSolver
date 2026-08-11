#!/usr/bin/env python3
"""
二进制分析模块
使用pwntools进行全面的二进制分析
"""

import os
import re
import subprocess
from pwn import ELF, which

class BinaryAnalyzer:
    """二进制文件分析器"""
    
    def __init__(self, binary_path, verbose=True):
        self.binary_path = os.path.abspath(binary_path)
        self.verbose = verbose
        self.elf = ELF(binary_path, checksec=False)
        self._info = None
        self._protections = None
        
    def log(self, msg):
        if self.verbose:
            print(f"  [analyzer] {msg}", flush=True)
    
    def basic_info(self):
        """获取基本信息"""
        if self._info:
            return self._info
        
        elf = self.elf
        
        info = {
            'type': 'ELF',
            'arch': elf.arch,
            'bits': elf.bits,
            'entry': hex(elf.entry),
            'endian': 'little' if elf.endian == 'little' else 'big',
            'execstack': elf.execstack,
            'pie': elf.pie,
            'nx': elf.nx,
            'relro': elf.relro,
        }
        
        self._info = info
        return info
    
    def checksec(self):
        """安全机制检查"""
        if self._protections:
            return self._protections
        
        elf = self.elf
        
        protections = {
            'canary': elf.canary,
            'nx': elf.nx,
            'pie': elf.pie,
            'relro': elf.relro == 'Full',
            'partial_relro': elf.relro == 'Partial',
            'rwx_segments': elf.execstack,
        }
        
        self._protections = protections
        return protections
    
    def find_interesting_functions(self):
        """查找有趣的函数 — stripped binary aware"""
        elf = self.elf
        
        dangerous = []
        useful = []
        win = []
        implied_win = []  # 从字符串/PLT推断的win路径
        
        # === 1. 从symbols查找（stripped后只有PLT/GOT符号） ===
        dangerous_patterns = ['gets', 'scanf', 'read', 'fgets', 'getline',
                            'strcpy', 'strcat', 'sprintf', 'vsprintf',
                            'memcpy', 'memmove']
        useful_patterns = ['puts', 'printf', 'write', 'send', 'sendline',
                          'open', 'read', 'write', 'mprotect']
        win_patterns = ['system', 'execve', 'execvp', 'execl',
                       'win', 'shell', 'flag', 'cat_flag', 'get_flag',
                       'backdoor', 'admin', 'pwned', 'hacked']
        
        for name, addr in elf.symbols.items():
            name_lower = name.lower()
            if any(skip in name for skip in ['__']):
                continue
            if addr == 0:
                continue
            
            for pat in dangerous_patterns:
                if pat in name_lower and '@' not in name:
                    dangerous.append((name, hex(addr)))
                    break
            for pat in useful_patterns:
                if pat in name_lower and '@' not in name:
                    useful.append((name, hex(addr)))
                    break
            for pat in win_patterns:
                if pat in name_lower and '@' not in name and 'plt.' not in name and 'got.' not in name:
                    win.append((name, hex(addr)))
                    break
        
        # === 2. PLT分析（stripped下仍可用！） ===
        # PLT中的危险函数
        for name in elf.plt:
            name_lower = name.lower()
            for pat in dangerous_patterns:
                if pat in name_lower:
                    if (name, hex(elf.plt[name])) not in dangerous:
                        dangerous.append((f'plt.{name}', hex(elf.plt[name])))
                    break
            for pat in useful_patterns:
                if pat in name_lower:
                    if (name, hex(elf.plt[name])) not in useful:
                        useful.append((f'plt.{name}', hex(elf.plt[name])))
                    break
        
        # === 3. 字符串推断 (stripped下仍可用！) ===
        strings = self.find_interesting_strings()
        has_binsh = any('/bin/sh' in s for s in strings)
        has_flag = any('flag' in s.lower() for s in strings)
        has_shell = any('shell' in s.lower() for s in strings)
        
        # 如果有system@plt + "/bin/sh"字符串 → implied win
        if 'system' in elf.plt:
            system_addr = elf.plt['system']
            if has_binsh:
                implied_win.append(('system@plt+/bin/sh', hex(system_addr)))
            elif has_shell:
                implied_win.append(('system@plt+shell', hex(system_addr)))
            else:
                implied_win.append(('system@plt', hex(system_addr)))
        
        # execve@plt也是win目标
        if 'execve' in elf.plt:
            implied_win.append(('execve@plt', hex(elf.plt['execve'])))
        
        # === 4. 反汇编分析（找call system@plt的代码） ===
        try:
            result = subprocess.run(
                ['objdump', '-d', '-M', 'intel', self.binary_path],
                capture_output=True, text=True, timeout=30
            )
            disasm = result.stdout
            
            # 找 "call.*system@plt" 模式
            import re
            for match in re.finditer(r'call\s+.*<([^>]+)>', disasm):
                target = match.group(1)
                if 'system' in target.lower() or 'execve' in target.lower():
                    addr_match = re.search(r'^\s*([0-9a-f]+):', 
                                          disasm[:match.start()].split('\n')[-1])
                    if addr_match:
                        implied_win.append((f'calls_{target}', f'0x{addr_match.group(1)}'))
                        break
            
            # 统计危险调用
            danger_calls = 0
            for match in re.finditer(r'call\s+.*<(gets|scanf|read)@plt>', disasm):
                danger_calls += 1
            if danger_calls > 0:
                self._danger_call_count = danger_calls
            
            # === 堆菜单检测: free/calloc + scanf(菜单) + bss索引数组 ===
            self._heap_menu = self._detect_heap_menu(disasm)
            
            # === 新增: 数组溢出/负索引检测 ===
            self._array_overflow = self._detect_array_overflow(disasm)
            
            # === 新增: PRNG检测 ===
            self._prng_info = self._detect_prng_usage(disasm)
            
            # === 新增: Go binary检测 ===
            self._is_go_binary = self._detect_go_binary(disasm)
            
            # === 新增: 栈提升/栈迁移检测 ===
            self._stack_pivot = self._detect_stack_pivot(disasm)
            
        except Exception:
            pass
        
        return {
            'dangerous': dangerous,
            'useful': useful,
            'win': win,
            'implied_win': implied_win,
            'has_binsh': has_binsh,
            'has_flag': has_flag,
            'plt_functions': list(elf.plt.keys()),
            'got_functions': list(elf.got.keys()),
            'stripped': elf.stripped,
            'heap_menu': getattr(self, '_heap_menu', {}),
            'array_overflow': getattr(self, '_array_overflow', {}),
            'prng_info': getattr(self, '_prng_info', {}),
            'is_go_binary': getattr(self, '_is_go_binary', False),
            'stack_pivot': getattr(self, '_stack_pivot', {}),
        }
    
    def _detect_heap_menu(self, disasm):
        """检测堆菜单题: free/calloc + scanf循环(菜单选择) + bss索引数组
        
        典型模式 (如 ctf.show 堆题):
          - call calloc@plt (Add)
          - call free@plt   (Delete, 且不置NULL -> UAF)
          - call scanf@plt  (菜单选项输入)
          - bss数组索引存取: lea rax,[rip+X]; mov [rax+idx*8], r (chunk指针数组)
        """
        import re
        info = {'heap_menu': False, 'free_count': 0, 'calloc_count': 0,
                'scanf_count': 0, 'ptr_array': None, 'size_array': None,
                'menu_options': None}
        
        has_free = '<free@plt>' in disasm
        has_calloc = '<calloc@plt>' in disasm or '<malloc@plt>' in disasm
        has_scarf = '<__isoc99_scanf@plt>' in disasm
        if not (has_free and has_calloc and has_scarf):
            return info
        
        # 统计调用次数 (菜单题通常每个功能调用一次)
        info['free_count'] = len(re.findall(r'call\s+.*<free@plt>', disasm))
        info['calloc_count'] = len(re.findall(r'call\s+.*<calloc@plt>', disasm)) + \
                               len(re.findall(r'call\s+.*<malloc@plt>', disasm))
        info['scanf_count'] = len(re.findall(r'call\s+.*<__isoc99_scanf@plt>', disasm))
        
        # bss数组检测: lea rax,[rip+X] 后跟 mov [rax+idx*8], r (存指针) 
        # 或 mov eax,[rax+idx*4] (存size)
        ptr_arrays = set()
        for m in re.finditer(r'lea\s+rax,\s*\[rip\+([0-9a-f]+)\]\s*\n\s*([0-9a-f]+):\s+(?:mov|add|lea)\s+\w+,\s*\[(?:rdx|rcx|rax)\*[48]', disasm):
            ptr_arrays.add(m.group(1))
        
        # 更宽松: 找 "lea rax,[rip+X]" 后带 *8 索引的模式 (指针数组)
        for m in re.finditer(r'lea\s+rax,\[rip\+([0-9a-f]+)\][^\n]*\n(?:[^\n]*\n){0,3}[^\n]*\*8[^\n]*', disasm):
            ptr_arrays.add(m.group(1))
        
        # 菜单判定: free+calloc都有 + (scanf次数>=3 或 指针数组存在)
        if info['free_count'] >= 1 and info['calloc_count'] >= 1 and \
           (info['scanf_count'] >= 3 or len(ptr_arrays) >= 1):
            info['heap_menu'] = True
            if ptr_arrays:
                info['ptr_array'] = sorted(ptr_arrays)[0]
            # 尝试从rodata找菜单选项 (A/S/E/D 模式)
            try:
                result = subprocess.run(['objdump', '-s', '-j', '.rodata', self.binary_path],
                                        capture_output=True, text=True, timeout=10)
                for line in result.stdout.split('\n'):
                    if any(c in line for c in ['1-A', '2-S', '3-E', '4-D', '5-Q', '1.A', '2.S']):
                        info['menu_options'] = line.strip()
                        break
            except Exception:
                pass
        return info
    
    def _detect_array_overflow(self, disasm):
        """检测数组溢出/负索引漏洞 (Badboy风格)
        
        特征:
        - scanf("%ld"/"%d") 读取索引 → 无符号转有符号
        - 数组访问: mov eax,[rax+rdx*N] 无边界检查
        - 输出: write(fd, &buf[idx], len) 越界读
        - 输入: read/scanf 写入 &buf[idx]
        """
        info = {'array_overflow': False, 'negative_index_possible': False,
                'leak_possible': False, 'write_possible': False}
        
        # 检测: scanf读取长整数 → 用作数组索引
        has_scanf_ld = bool(re.search(r'(?:%ld|%d).*__isoc99_scanf', disasm))
        has_scanf = bool(re.search(r'call\s+.*<__isoc99_scanf@plt>', disasm))
        
        # 检测: 通过write输出buf+idx*N的内容 (越界读)
        write_patterns = re.findall(
            r'call\s+.*<write@plt>.*\n(?:.*\n){0,10}',
            disasm, re.DOTALL
        )
        
        # 检测: lea rax,[rax+rdx*N] → 无边界检查的数组访问
        unbounded_access = bool(re.search(
            r'(?:lea|mov)\s+\w+,\s*\[\w+\+r\w+\*[148]\]', disasm
        ))
        
        # 检测: 负索引可能性 (有符号比较缺失)
        neg_index = bool(re.search(r'movsxd|cdqe|movsx', disasm))
        
        if has_scanf and unbounded_access:
            info['array_overflow'] = True
            info['negative_index_possible'] = neg_index  # movsxd/etc present → negative index IS possible
            info['leak_possible'] = bool(re.search(r'call\s+.*<write@plt>', disasm))
            info['write_possible'] = bool(re.search(
                r'call\s+.*<(?:read|fgets|gets)@plt>', disasm
            ))
        
        return info
    
    def _detect_prng_usage(self, disasm):
        """检测PRNG使用 (s.s.a.l风格)
        
        特征:
        - srand(time) / srand(seed) → 可预测种子
        - rand() → 伪随机序列可复现
        """
        info = {'prng_detected': False, 'srand_found': False,
                'rand_found': False, 'seed_source': None}
        
        has_srand = bool(re.search(r'call\s+.*<srand@plt>', disasm))
        has_rand = bool(re.search(r'call\s+.*<rand@plt>', disasm))
        
        if has_srand or has_rand:
            info['prng_detected'] = True
            info['srand_found'] = has_srand
            info['rand_found'] = has_rand
            
            # 检查种子来源
            if has_srand:
                # srand前是否调用time(0)
                if re.search(r'call\s+.*<time@plt>', disasm):
                    info['seed_source'] = 'time(0)'
                elif re.search(r'mov\s+edi,\s*(0x[0-9a-fA-F]+)', disasm):
                    m = re.search(r'mov\s+edi,\s*(0x[0-9a-fA-F]+)', disasm)
                    info['seed_source'] = f'constant: {m.group(1)}'
                else:
                    info['seed_source'] = 'user_input (possibly)'
        
        return info
    
    def _detect_go_binary(self, disasm):
        """检测Go编译的二进制 (ESCAPE GO BOX风格)
        
        特征:
        - runtime.morestack / runtime.newstack
        - go:itab 符号
        - 大量 runtime. 前缀函数
        """
        go_indicators = [
            'runtime.morestack', 'runtime.newstack', 'runtime.gcBgMarkWorker',
            'runtime.main', 'runtime.init', 'type..eq.',
            'go:itab', 'sync.', 'fmt.', 'os.',
        ]
        
        score = 0
        for indicator in go_indicators:
            if indicator in disasm:
                score += 1
        
        # Go二进制通常非常大且有很多独特符号
        has_many_runtime = len(re.findall(r'runtime\.\w+', disasm)) > 10
        
        return score >= 3 or has_many_runtime
    
    def _detect_stack_pivot(self, disasm):
        """检测栈提升/栈迁移模式 (yes_or_no风格)
        
        特征:
        - 重复调用leave;ret → 栈提升
        - add rsp, N; ret → 跳帧
        - xchg rsp, rax/rsi/rdi → 栈迁移
        - 函数返回值未校验 → 可反复调用覆盖栈
        """
        info = {'stack_pivot': False, 'stack_lift': False,
                'stack_migrate': False, 'repeated_call': False}
        
        # 检测leave;ret (栈提升)
        leave_ret = len(re.findall(r'leave\s*\n\s*[0-9a-f]+:\s*ret', disasm))
        if leave_ret >= 2:
            info['stack_lift'] = True
            info['stack_pivot'] = True
        
        # 检测xchg rsp (栈迁移)
        if re.search(r'xchg\s+(?:rax|rsi|rdi|rcx),\s*rsp', disasm):
            info['stack_migrate'] = True
            info['stack_pivot'] = True
        
        # 检测add rsp, N; ret 模式
        add_rsp_ret = len(re.findall(r'add\s+rsp,\s*0x[0-9a-f]+\s*\n\s*[0-9a-f]+:\s*ret', disasm))
        if add_rsp_ret >= 1:
            info['stack_lift'] = True
            info['stack_pivot'] = True
        
        return info
    
    def find_interesting_strings(self):
        """查找有趣字符串"""
        interesting = []
        
        patterns = [
            '/bin/sh', '/bin/bash', 'cat flag', 'flag',
            'password', 'admin', 'secret', 'shell',
        ]
        
        try:
            # 使用strings命令
            result = subprocess.run(
                ['strings', self.binary_path],
                capture_output=True, text=True, timeout=10
            )
            for line in result.stdout.split('\n'):
                line = line.strip()
                for pat in patterns:
                    if pat in line.lower():
                        interesting.append(line)
                        break
        except Exception:
            pass
        
        return interesting
    
    def find_buffer_sizes(self):
        """通过反汇编估计缓冲区大小"""
        buffers = []
        
        try:
            # 使用objdump查找sub rsp, XXX 指令
            result = subprocess.run(
                ['objdump', '-d', '-M', 'intel', self.binary_path],
                capture_output=True, text=True, timeout=30
            )
            
            # 搜索函数开头的栈分配
            for line in result.stdout.split('\n'):
                # sub rsp, 0xNN
                m = re.search(r'sub\s+(rsp|esp),\s*(0x[0-9a-fA-F]+)', line)
                if m:
                    size = int(m.group(2), 16)
                    if 0x10 <= size <= 0x2000:  # 合理范围
                        # 查找所属函数
                        buffers.append({'type': 'stack_frame', 'size': size, 'hex': m.group(2)})
                
                # push rbp; mov rbp, rsp; sub rsp, XXX
                # lea 指令中的偏移
                m = re.search(r'(?:lea|mov)\s+\w+,\s*\[(?:rbp|ebp|rsp|esp)([+-])(0x[0-9a-fA-F]+)\]', line)
                if m:
                    offset = int(m.group(2), 16)
                    if offset > 0:
                        buffers.append({'type': 'buffer_offset', 'size': offset, 'hex': m.group(2)})
        except Exception:
            pass
        
        return buffers
    
    def disassemble_function(self, func_name):
        """反汇编指定函数"""
        try:
            result = subprocess.run(
                ['objdump', '-d', '-M', 'intel', '--disassemble=' + func_name, self.binary_path],
                capture_output=True, text=True, timeout=10
            )
            return result.stdout
        except Exception:
            return ""
    
    def get_plt_got_info(self):
        """获取PLT/GOT信息"""
        elf = self.elf
        info = {
            'plt': {},
            'got': {},
        }
        
        for name in elf.plt:
            info['plt'][name] = hex(elf.plt[name])
        
        for name in elf.got:
            info['got'][name] = hex(elf.got[name])
        
        return info
    
    def summary(self):
        """生成分析摘要"""
        info = self.basic_info()
        protections = self.checksec()
        functions = self.find_interesting_functions()
        plt_got = self.get_plt_got_info()
        
        summary = {
            'file': os.path.basename(self.binary_path),
            'arch': info['arch'],
            'bits': info['bits'],
            'protections': protections,
            'dangerous_functions': functions['dangerous'],
            'win_functions': functions['win'],
            'plt_count': len(plt_got['plt']),
            'got_count': len(plt_got['got']),
        }
        
        return summary
