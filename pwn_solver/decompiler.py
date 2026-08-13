#!/usr/bin/env python3
"""轻量反编译器 — IDA F5 风格的伪 C 视图

从 objdump 反汇编生成伪 C:
- 只显示 main 及其调用链内的用户函数 (libc/plt 调用不展开)
- 字符串字面量、调用参数 (rdi/rsi/rdx 简单追踪)、栈变量声明
- 危险调用/溢出点/canary 校验以注释 + tag 标注
"""
import re
import subprocess

# 标注 tag 与 GUI 的 DISASM_TAGS 一致
TAG_DANGER = 'danger_call'
TAG_OVERFLOW = 'overflow'
TAG_WIN = 'win'
TAG_CANARY = 'canary'
TAG_FMT = 'fmt'

DANGER_SYMS = {'gets', 'read', 'scanf', '__isoc99_scanf', '__isoc23_scanf',
               'strcpy', 'strcat', 'sprintf', 'memcpy', 'memmove'}


def parse_objdump(binary_path):
    """反汇编 → {函数名: [(addr:int, insn:str, comment:str)]}"""
    r = subprocess.run(['objdump', '-d', '-M', 'intel', binary_path],
                       capture_output=True, text=True, timeout=60)
    disasm = r.stdout
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
        return name in funcs and '@plt' not in name and not name.startswith('_')

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
            # 6) cmp + 条件跳转 → if 结构
            m = re.match(r'cmp\s+(\w+),\s*(0x[0-9a-f]+)', insn_body)
            if m:
                pending_cond = (m.group(1), m.group(2))
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
        emit('', None)
    return '\n'.join(lines_out), annot


if __name__ == '__main__':
    import sys
    text, annot = decompile(sys.argv[1])
    print(text)
    print('--- annot:', {k: v for k, v in sorted(annot.items()) if v})
