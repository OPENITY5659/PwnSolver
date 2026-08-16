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
            'inner_overflows': getattr(self, '_inner_overflows', []),
            'input_stages': self._detect_input_stages(),
        }
    
    def _detect_input_stages(self):
        """检测多阶段输入模式(如s.s.a.l: read→scanf→read)。"""
        try:
            result = subprocess.run(
                ['objdump', '-d', '-M', 'intel', self.binary_path],
                capture_output=True, text=True, timeout=15
            )
            disasm = result.stdout
        except:
            return []
        
        stages = []
        current_func = None
        read_size = 0
        func_pattern = re.compile(r'^([0-9a-f]+)\s+<([^>]+)>:')
        read_pattern = re.compile(r'call\s+.*<read@plt>')
        scanf_pattern = re.compile(r'call\s+.*<__isoc99_scanf@plt>')
        mov_edx_pat = re.compile(r'mov\s+edx,\s*(0x[0-9a-fA-F]+)')
        
        order = 0
        for line in disasm.split('\n'):
            fm = func_pattern.search(line)
            if fm:
                current_func = fm.group(2)
                continue
            if current_func is None:
                continue
            mm = mov_edx_pat.search(line)
            if mm:
                read_size = int(mm.group(1), 16)
                continue
            if read_pattern.search(line):
                stages.append({'type':'read','size':read_size,'function':current_func,'order':order})
                order += 1
                read_size = 0
            elif scanf_pattern.search(line):
                stages.append({'type':'scanf','size':0,'function':current_func,'order':order})
                order += 1
        
        return stages
    
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

        # BadBoy 签名（CTFshow 2024 元旦水友赛 pwn1）：
        #   scanf("%ld") -> 有符号 byte 索引 -> write(fd, stack_buf+idx, len) 泄露
        #   scanf("%lld") -> 检查 <=8 的负数索引 -> read(0, stack_buf+idx, 3) 任意写
        try:
            result = subprocess.run(
                ['strings', self.binary_path],
                capture_output=True, text=True, timeout=10
            )
            strs = result.stdout or ''
            if ('i am bad boy' in strs and 'HaHaHa' in strs
                    and 'so can you fell me' in strs
                    and '<write@plt>' in disasm and '<read@plt>' in disasm
                    and re.search(r'movsxd\s+r\w+,\s*e?d', disasm)):
                info.update({
                    'array_overflow': True,
                    'badboy_style': True,
                    'negative_index_possible': True,
                    'leak_possible': True,
                    'write_possible': True,
                    'strategy_hint': 'badboy_leak_stack_libc_then_overwrite_puts_got',
                })
        except Exception:
            pass

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
        """通过反汇编估计缓冲区大小，包括嵌套函数中的read()溢出"""
        buffers = []
        
        try:
            result = subprocess.run(
                ['objdump', '-d', '-M', 'intel', self.binary_path],
                capture_output=True, text=True, timeout=30
            )
            disasm = result.stdout
            
            # 搜索函数开头的栈分配
            for line in disasm.split('\n'):
                # sub rsp, 0xNN
                m = re.search(r'sub\s+(rsp|esp),\s*(0x[0-9a-fA-F]+)', line)
                if m:
                    size = int(m.group(2), 16)
                    if 0x10 <= size <= 0x2000:
                        buffers.append({'type': 'stack_frame', 'size': size, 'hex': m.group(2)})
                
                # lea/mov 指令中的偏移 (buffer到rbp的距离)
                m = re.search(r'(?:lea|mov)\s+\w+,\s*\[(?:rbp|ebp|rsp|esp)([+-])(0x[0-9a-fA-F]+)\]', line)
                if m:
                    offset = int(m.group(2), 16)
                    if offset > 0:
                        buffers.append({'type': 'buffer_offset', 'size': offset, 'hex': m.group(2)})
            
            # === 新增: 检测嵌套函数中的read()溢出 ===
            # 找所有 read(0, rsp+XX, size) 调用，分析size是否超过到ret addr的距离
            inner_overflows = self._find_inner_read_overflows(disasm)
            buffers.extend(inner_overflows)
            
        except Exception:
            pass
        
        return buffers
    
    def _find_inner_read_overflows(self, disasm):
        """检测函数内部read()调用造成的栈溢出。
        
        模式: sub rsp, N / push rX ... → read(0, rsp+off, size)
        计算: 从buffer位置到返回地址的距离是否 < size
        """
        overflows = []
        lines = disasm.split('\n')
        
        # 找每个函数: 函数名行 → 收集push和sub → 找read调用
        func_pattern = re.compile(r'^([0-9a-f]+)\s+<([^>]+)>:')
        push_pattern = re.compile(r'\s+push\s+r')
        sub_pattern = re.compile(r'\s+sub\s+(rsp|esp),\s*(0x[0-9a-fA-F]+)')
        read_pattern = re.compile(r'.*call.*<read@plt>')
        # 找read前设置参数的指令: mov edx, size (rdx=第三个参数=count)
        mov_edx_pattern = re.compile(r'mov\s+e?dx,\s*(0x[0-9a-fA-F]+)')
        # 找read前设置rsi的指令: lea rsi,[rsp+XX] 或 mov rsi,rsp 等
        lea_rsi_pattern = re.compile(r'lea\s+(rsi|esi),\s*\[(rsp|esp)\+?(0x[0-9a-fA-F]+)?\]')
        
        current_func = None
        frame_size = 0
        push_count = 0
        sub_amount = 0
        read_size = None
        read_buf_offset = 0
        
        for line in lines:
            # 检测函数开始
            fm = func_pattern.search(line)
            if fm:
                current_func = fm.group(2)
                frame_size = 0
                push_count = 0
                sub_amount = 0
                read_size = None
                read_buf_offset = 0
                continue
            
            if current_func is None:
                continue
            
            # 统计push
            if push_pattern.search(line):
                push_count += 1
                continue
            
            # 统计sub rsp
            sm = sub_pattern.search(line)
            if sm:
                sub_amount = int(sm.group(2), 16)
                continue
            
            # 检测mov edx (read的第三个参数 = 读取大小)
            mm = mov_edx_pattern.search(line)
            if mm and read_size is None:
                read_size = int(mm.group(1), 16)
                continue
            
            # 检测lea rsi (read的第二个参数 = buffer地址)
            lm = lea_rsi_pattern.search(line)
            if lm and read_buf_offset == 0:
                off = lm.group(3)
                read_buf_offset = int(off, 16) if off else 0
                continue
            
            # 检测call read@plt
            if read_pattern.search(line) and read_size and current_func != 'main':
                # 计算: frame_size = push_count*8 + sub_amount
                # 返回地址在 frame_size 之上
                # buffer在 rsp + read_buf_offset
                # 到返回地址的距离 = frame_size - read_buf_offset
                frame_size = push_count * 8 + sub_amount
                dist_to_ret = frame_size - read_buf_offset
                
                if read_size > dist_to_ret and dist_to_ret > 0:
                    overflows.append({
                        'type': 'inner_read_overflow',
                        'function': current_func,
                        'frame_size': frame_size,
                        'buf_offset': read_buf_offset,
                        'read_size': read_size,
                        'dist_to_ret': dist_to_ret,
                        'overflow_bytes': read_size - dist_to_ret,
                        'pushes': push_count,
                    })
                # 重置，可能同一函数有多次read
                read_size = None
                read_buf_offset = 0
        
        if overflows:
            self._inner_overflows = overflows
        return overflows
    
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
