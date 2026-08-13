#!/usr/bin/env python3
"""轻量反编译器 — IDA F5 风格的伪 C 视图

从 objdump 反汇编生成伪 C:
- 只显示 main 及其调用链内的用户函数 (libc/plt 调用不展开)
- 字符串字面量、调用参数 (rdi/rsi/rdx 简单追踪)、栈变量声明
- 危险调用/溢出点/canary 校验以注释 + tag 标注
- 经典加解密算法静态识别 (base64/xor/rot13/hex/AES/MD5/TEA)
"""
import os
import re
import subprocess

_DISASM_CACHE = {}

# 标注 tag 与 GUI 的 DISASM_TAGS 一致
TAG_DANGER = 'danger_call'
TAG_OVERFLOW = 'overflow'
TAG_WIN = 'win'
TAG_CANARY = 'canary'
TAG_FMT = 'fmt'
TAG_CRYPTO = 'crypto'

DANGER_SYMS = {'gets', 'read', 'scanf', '__isoc99_scanf', '__isoc23_scanf',
               'strcpy', 'strcat', 'sprintf', 'memcpy', 'memmove'}

# 标准 C 库/libc 函数名 — 静态链接 (musl/glibc) 下无 @plt 后缀, 按名过滤不展开
LIBC_SYMS = {
    # stdio
    'setvbuf', 'setbuf', 'printf', 'puts', 'putchar', 'fopen', 'fclose',
    'fwrite', 'fread', 'fgets', 'fputs', 'fputc', 'fgetc', 'getchar',
    'fflush', 'feof', 'ferror', 'fseek', 'ftell', 'rewind', 'fprintf',
    'sprintf', 'snprintf', 'scanf', 'fscanf', 'vprintf', 'vfprintf',
    'perror', 'ungetc', 'fgets_unlocked', 'clearerr', 'fileno', 'fdopen',
    'tmpfile', 'remove', 'rename',
    # string/memory
    'memset', 'memcpy', 'memmove', 'memcmp', 'memchr', 'strlen', 'strcpy',
    'strncpy', 'strcat', 'strncat', 'strcmp', 'strncmp', 'strchr',
    'strrchr', 'strstr', 'strtok', 'strdup', 'strndup', 'strspn',
    'strcspn', 'strpbrk', 'strerror', 'strcoll', 'strxfrm',
    # stdlib
    'malloc', 'calloc', 'realloc', 'free', 'exit', 'abort', 'atexit',
    'atoi', 'atol', 'atoll', 'strtol', 'strtoul', 'strtod', 'abs', 'labs',
    'rand', 'srand', 'qsort', 'bsearch', 'getenv', 'setenv', 'putenv',
    'system', 'getpid', 'sleep', 'usleep', 'alarm', 'signal',
    # ctype/math/io
    'isalpha', 'isdigit', 'isalnum', 'isspace', 'islower', 'isupper',
    'tolower', 'toupper', 'isprint', 'iscntrl',
    'pow', 'sqrt', 'sin', 'cos', 'tan', 'fabs', 'floor', 'ceil', 'log',
    'exp', 'atan2', 'fmod',
    # 系统
    'open', 'close', 'read', 'write', 'lseek', 'stat', 'fstat', 'lstat',
    'access', 'unlink', 'mkdir', 'rmdir', 'chdir', 'getcwd', 'chmod',
    'fcntl', 'dup', 'dup2', 'pipe', 'socket', 'connect', 'bind', 'listen',
    'accept', 'send', 'recv', 'execve', 'execv', 'execl', 'fork', 'wait',
    'waitpid', 'kill', 'mmap', 'munmap', 'mprotect', 'ioctl', 'gettimeofday',
    'clock', 'time', 'nanosleep', 'syscall', 'prctl', 'ptrace', 'select',
    'poll', 'epoll_create', 'epoll_ctl', 'epoll_wait',
    # 内部/musl 实现函数 (静态链接常见)
    '__lockfile', '__unlockfile', '__uflow', '__fwritex', '__fdopen',
    '__fmodeflags', '__syscall_cp', '__syscall_ret', '__errno_location',
    '__strchrnul', '__ofl_lock', '__ofl_unlock', '__unlist_locked_file',
    '__stack_chk_fail', '__libc_start_main', '__libc_csu_init',
    '__libc_csu_fini', '__ctype_b_loc', '__toupper_loc', '__tolower_loc',
    '__overflow', '__stdio_read', '__stdio_write', '__stdio_seek',
    '__stdio_close', '__towrite', '__towrite_needs_stdio_exit',
    '__fopen_rb_ca', '__restore_rt', '__restore', '_exit', '_start',
    '__init_libc', '__init_tls', '__init_ssp', 'dummy1', '__dls2',
    '__dls2b', '__dls3', '__libc_exit_fini', '__funcs_on_exit',
    '__stdio_exit', '__stdio_exit_needed', '__init_security',
    '__libc_start_init', '__libc_start_main_stage2',
}

# ========= 经典加解密算法静态识别 =========
B64_TABLE = b'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/'
B64_TABLE_URL = b'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_'
HEX_TABLE = b'0123456789abcdef'
AES_SBOX_HEAD = bytes.fromhex('637c777bf26b6fc53001672bfed7ab76')
MD5_IV = bytes.fromhex('0123456789abcdeffedcba9876543210')   # MD5 初始化常量 (小端序列)
TEA_DELTA = bytes.fromhex('b979379e')


def detect_crypto(disasm, elf):
    """静态识别经典加解密算法

    返回: [{'type': 'base64'|'xor'|'rot13'|'hex'|'aes'|'md5'|'tea',
           'desc': '人类可读描述', 'evidence': '证据'}]
    """
    found = []
    data = b''
    try:
        data = elf.data or b''
    except Exception:
        pass

    # 1. Base64 (标准/URL-safe 字母表)
    if B64_TABLE in data:
        off = data.find(B64_TABLE)
        found.append({'type': 'base64', 'desc': 'Base64 编码/解码',
                      'evidence': f'标准字母表 @ +0x{off:x}'})
    elif B64_TABLE_URL in data:
        off = data.find(B64_TABLE_URL)
        found.append({'type': 'base64', 'desc': 'Base64 (URL-safe)',
                      'evidence': f'URL-safe 字母表 @ +0x{off:x}'})
    # 2. Hex 编码
    if HEX_TABLE in data and b'%02x' in data.lower():
        found.append({'type': 'hex', 'desc': 'Hex 编码 ("%02x")',
                      'evidence': '"%02x" 格式串'})
    # 3. XOR 加密 (XOR 非零单字节立即数; 排除 xor reg,reg 清零与静态库噪声)
    keys = set()
    for m in re.finditer(r'xor\s+(?:byte\s+)?ptr\s+\[[^\]]+\],\s*(0x[0-9a-f]+)', disasm, re.I):
        k = int(m.group(1), 16)
        if 0 < k <= 0xff:
            keys.add(k)
    for m in re.finditer(r'xor\s+(?:al|bl|cl|dl),\s*(0x[0-9a-f]+)', disasm, re.I):
        k = int(m.group(1), 16)
        if 0 < k <= 0xff:
            keys.add(k)
    for m in re.finditer(r'xor\s+(?:e?ax|e?bx|e?cx|e?dx|esi|edi),\s*(0x[0-9a-f]+)', disasm, re.I):
        k = int(m.group(1), 16)
        if 0 < k <= 0xff:
            keys.add(k)
    # 静态库中会出现大量互不相关的 xor 立即数 — 不同 key 超过 3 个视为噪声
    if keys and len(keys) <= 3:
        found.append({'type': 'xor', 'desc': 'XOR 加密',
                      'evidence': 'key=' + ', '.join(hex(k) for k in sorted(keys))})
    # 4. ROT13 (字母范围比较 + ±0xd)
    has_rot_add = bool(re.search(r'add\s+(?:al|bl|cl|dl),\s*0xd\b', disasm, re.I)) or \
                  bool(re.search(r'sub\s+(?:al|bl|cl|dl),\s*0xd\b', disasm, re.I))
    has_alpha_cmp = bool(re.search(r'cmp\s+(?:al|bl|cl|dl),\s*0x(?:61|7a|41|5a)\b', disasm, re.I))
    if has_rot_add and has_alpha_cmp:
        found.append({'type': 'rot13', 'desc': 'ROT13 字母轮换',
                      'evidence': '±0xd + a/z/A/Z 范围比较'})
    # 5. AES S-box
    if AES_SBOX_HEAD in data:
        off = data.find(AES_SBOX_HEAD)
        found.append({'type': 'aes', 'desc': 'AES 加密 (S-box)',
                      'evidence': f'S-box 特征序列 @ +0x{off:x}'})
    # 6. MD5 初始化常量
    if MD5_IV in data:
        off = data.find(MD5_IV)
        found.append({'type': 'md5', 'desc': 'MD5 哈希',
                      'evidence': f'IV 常量 @ +0x{off:x}'})
    # 7. TEA 系列 (delta 0x9e3779b9)
    if TEA_DELTA in data or re.search(r'9e3779b9|61c88647', disasm, re.I):
        found.append({'type': 'tea', 'desc': 'TEA/XTEA 分组加密',
                      'evidence': 'delta 0x9e3779b9'})
    return found


def _reg_display(reg):
    """寄存器 → 伪 C 显示名 (避免直接冒出 eax 这种奇怪名字)"""
    return {
        'rax': 'retval', 'eax': 'retval', 'al': 'retval',
        'rbx': 'x1', 'ebx': 'x1',
        'rcx': 'x2', 'ecx': 'x2',
        'rdx': 'x3', 'edx': 'x3',
        'rsi': 'x4', 'esi': 'x4',
        'rdi': 'x5', 'edi': 'x5',
        'r8': 'x6', 'r9': 'x7',
    }.get(reg, reg)


def parse_objdump(binary_path):
    """反汇编 → {函数名: [(addr:int, insn:str, comment:str)]}"""
    r = subprocess.run(['objdump', '-d', '-M', 'intel', binary_path],
                       capture_output=True, text=True, timeout=60)
    disasm = r.stdout
    _DISASM_CACHE[os.path.abspath(binary_path)] = disasm
    funcs = {}
    cur = None
    for line in disasm.split('\n'):
        fm = re.match(r'^([0-9a-f]+)\s+<([^>]+)>:\s*$', line)
        if fm:
            cur = fm.group(2)
            funcs[cur] = []
            continue
        if cur is None:
            continue
        m = re.match(r'^\s*([0-9a-f]+):\s*(.*)$', line)
        if m:
            insn = m.group(2).strip()
            comment = ''
            if '#' in insn:
                insn, comment = insn.split('#', 1)
                insn = insn.strip()
                comment = comment.strip()
            funcs[cur].append((int(m.group(1), 16), insn, comment))
    return funcs


def _insn_mnemonic(insn):
    return insn.split('\t')[-1].split(' ')[0]


def _call_target(insn, funcs_by_addr):
    """call 指令 → (目标名, 是否用户函数)"""
    m = re.search(r'call\s+([0-9a-f]+)\s*(?:<([^>]+)>)?', insn)
    if not m:
        return None, False
    addr = int(m.group(1), 16)
    name = m.group(2)
    if name:
        return name, False  # 有名函数: 可能是 plt/用户函数, 由调用者判断
    return (hex(addr), True)  # 无符号: 直接地址 (用户函数)


def decompile(binary_path, elf_strings=None):
    """生成伪 C 文本与行标注

    返回: (text, annot) — annot: {行号: tag}
    """
    from pwn import ELF
    elf = ELF(binary_path, checksec=False)
    funcs = parse_objdump(binary_path)
    # 地址 → 函数名
    addr_to_func = {}
    for fname, insns in funcs.items():
        if insns:
            addr_to_func[insns[0][0]] = fname

    # 从 main 出发收集调用链内的用户函数
    def is_user_func(name):
        return (name in funcs and '@plt' not in name
                and not name.startswith('_')
                and name not in LIBC_SYMS)

    visited = set()
    queue = ['main'] if 'main' in funcs else list(funcs)[:1]

    # win 候选函数强制显示 (解题目标)
    try:
        from pwn_solver.analyzer import BinaryAnalyzer
        an = BinaryAnalyzer(binary_path, verbose=False)
        finfo = an.find_interesting_functions()
        for name, addr in finfo.get('win', []) + finfo.get('implied_win', []):
            try:
                a = int(addr, 16) if isinstance(addr, str) else addr
            except Exception:
                continue
            for fname, insns in funcs.items():
                if insns and insns[0][0] == a and fname not in visited:
                    visited.add(fname)
                    queue.append(fname)
                    break
    except Exception:
        pass

    def collect_callees(fname):
        for addr, insn, comment in funcs.get(fname, []):
            m = re.search(r'call\s+[0-9a-f]+\s*<([^>]+)>', insn)
            if m:
                tgt = m.group(1)
                if is_user_func(tgt) and tgt not in visited:
                    visited.add(tgt)
                    queue.append(tgt)
            # 无符号 call (直接地址) → 用户函数
            m2 = re.search(r'call\s+([0-9a-f]+)\s*$', insn)
            if m2:
                a = int(m2.group(1), 16)
                if a in addr_to_func and addr_to_func[a] not in visited:
                    fn = addr_to_func[a]
                    if is_user_func(fn):
                        visited.add(fn)
                        queue.append(fn)

    visited.add(queue[0])
    i = 0
    while i < len(queue):
        collect_callees(queue[i])
        i += 1

    # 生成伪 C
    lines_out = []
    annot = {}

    def emit(line, tag=None):
        annot[len(lines_out)] = tag
        lines_out.append(line)

    def read_cstr(addr_hex):
        try:
            a = int(addr_hex, 16)
            s = elf.string(a)
            if s:
                return s.decode('latin-1', 'replace').replace('\n', '\\n')[:60]
        except Exception:
            pass
        return None

    for fname in queue:
        insns = funcs.get(fname, [])
        if not insns:
            continue
        start_addr = insns[0][0]
        emit(f'void {fname}() {{   // 0x{start_addr:x}')
        # 栈变量声明 (从 lea [rbp-0xNN] 推断缓冲区)
        buf_offs = set()
        for addr, insn, comment in insns:
            m = re.search(r'\[rbp-0x([0-9a-f]+)\]', insn)
            if m:
                buf_offs.add(int(m.group(1), 16))
        declared = set()
        max_off = max(buf_offs, default=0)
        for off in sorted(buf_offs):
            vname = 'buf' if off == max_off else f'var_{off:x}'
            if off not in declared:
                emit(f'    char {vname}[0x{off:x}];')
                declared.add(off)
        # 寄存器 → 表达式 简单追踪 (rdi/rsi/rdx/rax 参数)
        regs = {}
        pending_cond = None
        if_depth = 0

        def indent():
            return '    ' * (1 + if_depth)

        for addr, insn, comment in insns:
            insn_body = insn.split('\t')[-1]
            # 字符串引用 (lea [rip+X] 行的注释给出地址; 注释已去除 '#' 前缀)
            cstr = None
            m = re.search(r'([0-9a-f]+)\s*<', comment)
            if m:
                cstr = read_cstr(m.group(1))
            tag = None
            # 1) lea rax,[rip+X] → 字符串
            m = re.match(r'lea\s+([a-z0-9]+),\s*\[rip\+0x([0-9a-f]+)\]', insn_body)
            if m:
                if cstr:
                    regs[m.group(1).lstrip('e')] = f'"{cstr}"'
                continue
            # 2) mov 立即数/地址
            m = re.match(r'mov\s+(e?[a-z0-9]+),\s*(0x[0-9a-f]+)', insn_body)
            if m:
                reg = m.group(1).lstrip('e')
                val = m.group(2)
                if cstr:
                    regs[reg] = f'"{cstr}"'
                else:
                    regs[reg] = val if int(val, 16) > 9 else str(int(val, 16))
                continue
            # 3) mov reg, reg
            m = re.match(r'mov\s+(e?[a-z0-9]+),\s*(e?[a-z0-9]+)\s*$', insn_body)
            if m:
                dst = m.group(1).lstrip('e')
                src = m.group(2).lstrip('e')
                if src in regs:
                    regs[dst] = regs[src]
                continue
            # 4) lea rax,[rbp-X] → 局部变量
            m = re.match(r'lea\s+([a-z0-9]+),\s*\[rbp-0x([0-9a-f]+)\]', insn_body)
            if m:
                off = int(m.group(2), 16)
                vname = 'buf' if off == max_off else f'var_{off:x}'
                regs[m.group(1).lstrip('e')] = vname
                continue
            # 4b) lea rax,[rsp+X] → 栈变量 (musl 风格, rbp 帧外)
            m = re.match(r'lea\s+([a-z0-9]+),\s*\[rsp\+0x([0-9a-f]+)\]', insn_body)
            if m:
                off = int(m.group(2), 16)
                regs[m.group(1).lstrip('e')] = f'var_{off:x}'
                continue
            # 4c) mov reg, [rsp+X] / [rbp-X] → 读栈变量
            m = re.match(r'mov\s+([a-z0-9]+),\s*[a-z0-9]*\s*(?:QWORD|DWORD|BYTE)?\s*PTR\s*\[r(?:sp|bp)[+-]0x([0-9a-f]+)\]', insn_body)
            if m:
                off = int(m.group(2), 16)
                vname = 'buf' if off == max_off else f'var_{off:x}'
                regs[m.group(1).lstrip('e')] = vname
                continue
            # 5) call
            m = re.search(r'call\s+[0-9a-f]+\s*<([^>]+)>', insn_body)
            if m:
                tgt = m.group(1)
                arg_list = []
                seen = set()
                for r in ('rdi', 'rsi', 'rdx'):
                    v = regs.get(r)
                    if v is None or v in seen:
                        continue
                    seen.add(v)
                    arg_list.append(v)
                args = ', '.join(arg_list)
                if '@plt' in tgt:
                    sym = tgt.split('@')[0]
                    note = ''
                    if sym in DANGER_SYMS:
                        note = '   // !危险'
                        tag = TAG_DANGER
                    line_txt = f'{indent()}{sym}({args});{note}'
                elif is_user_func(tgt):
                    line_txt = f'{indent()}{tgt}();'
                else:
                    line_txt = f'{indent()}{tgt}({args});'
                # flag 相关字符串 → 绿色高亮
                if 'flag' in line_txt.lower():
                    tag = TAG_WIN
                emit(line_txt, tag)
                # 调用后参数寄存器失效 (避免残留到下一次调用)
                for r in ('rdi', 'rsi', 'rdx'):
                    regs.pop(r, None)
                continue
            # 无符号 call (直接地址)
            m = re.search(r'call\s+([0-9a-f]+)\s*$', insn_body)
            if m:
                a = int(m.group(1), 16)
                fn = addr_to_func.get(a)
                if fn and is_user_func(fn):
                    emit(f'{indent()}{fn}();')
                continue
            # 6) cmp + 条件跳转 → if 结构 (寄存器显示名映射, 如 eax→retval)
            m = re.match(r'cmp\s+(\w+),\s*(0x[0-9a-f]+)', insn_body)
            if m:
                pending_cond = (_reg_display(m.group(1)), m.group(2))
                continue
            m = re.match(r'j(?:e|ne|le|ge|a|b)\s+([0-9a-f]+)', insn_body)
            if m and pending_cond:
                op = '==' if m.group(0).startswith('je') else '!='
                emit(f'{indent()}if ({pending_cond[0]} {op} {pending_cond[1]}) {{')
                pending_cond = None
                if_depth += 1
                continue
            # 7) canary
            if 'fs:0x28' in insn_body:
                emit(f'{indent()}__stack_chk_check();   // canary 校验', TAG_CANARY)
                continue
            # 8) 返回
            if insn_body.startswith('ret'):
                while if_depth > 0:
                    if_depth -= 1
                    emit('    ' * (1 + if_depth) + '}')
                emit('}')
                continue
            # 其余指令 (mov 参数/lea 局部/push/pop/nop 等) 不输出 — 保持伪 C 干净
        emit('')
    
    # 加解密算法识别 (伪 C 顶部标注, 金色)
    disasm_raw = _DISASM_CACHE.get(os.path.abspath(binary_path), '')
    crypto = detect_crypto(disasm_raw, elf)
    if crypto:
        head_lines = [f'// [加解密识别] {", ".join(c["desc"] for c in crypto)}']
        for c in crypto:
            head_lines.append(f'//     {c["desc"]} — {c["evidence"]}')
        head_lines.append('')
        shift = len(head_lines)
        annot = {k + shift: v for k, v in annot.items()}
        for i in range(shift):
            annot[i] = TAG_CRYPTO
        lines_out = head_lines + lines_out
    return '\n'.join(lines_out), annot


if __name__ == '__main__':
    import sys
    text, annot = decompile(sys.argv[1])
    print(text)
    print('--- annot:', {k: v for k, v in sorted(annot.items()) if v})
