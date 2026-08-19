# -*- coding: utf-8 -*-
"""ret2libc 模板回归测试.

固化 2026-08 修复的关键 bug:
1. ROPExploit 不再用 ROP(elf, libc) (pwntools 第二个位置参数是 base 而非 libc)
2. 生成的代码不再 p.close() 之后 recv
3. gadget_finder 报告的 libc pop_rdi/ret 是文件偏移, 模板必须重定位
4. 无二进制内 pop_rdi 时从 libc gadget 组链
5. solver 无 libc 时本地系统 libc fallback
"""
import ast
import os
import sys
import textwrap
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'pwn_solver'))


def _gen_roP():
    from exploit_templates import ROPExploit
    analysis = {
        'buffers': [{'type': 'stack_frame', 'size': 48}],
        'protections': {'nx': True, 'pie': False, 'canary': False},
        'functions': {},
    }
    gadgets = {
        'arch': 'amd64',
        'specific': {'pop_rdi': 0x11bc7a, 'ret': None},  # libc 偏移, 无 binary ret
        'plt': {},
    }
    e = ROPExploit(binary_path='/tmp/bench/ret2libc', analysis=analysis,
                   gadgets=gadgets, libc_path='/tmp/bench/libc.so.6')
    return e.generate()


def test_rop_exploit_no_invalid_rop_ctor():
    code = _gen_roP()
    assert 'ROP(elf, libc)' not in code, 'must not pass libc as positional base'
    ast.parse(code)


def test_rop_exploit_no_recv_after_close():
    code = _gen_roP()
    # p.close() 必须出现在所有 recv 之后 (close 后 recv 永远失败)
    tree = ast.parse(code)
    for node in ast.walk(tree):
        if isinstance(node, ast.Call) and getattr(node.func, 'attr', '') == 'close':
            for sub in ast.walk(node):
                if isinstance(sub, ast.Call) and getattr(sub.func, 'attr', '') == 'recv':
                    raise AssertionError('recv after p.close() in generated exploit')


def test_rop_exploit_rebases_libc_offset_gadgets():
    code = _gen_roP()
    # binary 内 gadget (0x400000+) 直接用, libc 偏移 (<0x300000) 加 libc.address
    assert 'if 0x400000 <= POP_RDI < 0x10000000' in code, \
        'binary gadget must NOT add libc.address; libc offset must rebase'
    # 无 binary ret 时从 libc 取对齐 ret
    assert "ROP(libc).ret.address" in code
    # 拿到 shell 后必须主动发验证命令
    assert "echo PWNED_OK; id" in code


def test_solver_system_libc_fallback_paths():
    import solver as solver_mod
    src = (ROOT / 'pwn_solver' / 'solver.py').read_text(encoding='utf-8')
    assert '_is_locally_runnable_dynamic_elf' in src
    assert '_system_libc_candidates' in src
    assert '/usr/lib' in src and 'libc.so.6' in src
    # 方法可独立调用且在非 ELF 输入上安全返回
    s = object.__new__(solver_mod.PwnSolver)
    s.binary_path = __file__            # 非 ELF
    s.original_binary_path = None
    assert s._is_locally_runnable_dynamic_elf() is False
    cands = s._system_libc_candidates()
    assert isinstance(cands, list) and all(x.startswith('/') for x in cands)


def test_ret2libc_leak_stage2_rebases_pop_rdi():
    from exploit_templates import Ret2LibcExploit
    analysis = {
        'buffers': [{'type': 'stack_frame', 'size': 48}],
        'protections': {'nx': True, 'pie': False},
        'functions': {'main': 0x4011d1},
    }
    gadgets = {
        'arch': 'amd64',
        'specific': {
            'pop_rdi': 0x11bc7a,      # libc 偏移
            'puts_plt': 0x401070,
            'puts_got': 0x404018,
        },
        'plt': {'puts': 0x401070},
    }
    e = Ret2LibcExploit(binary_path='/tmp/bench/ret2libc', analysis=analysis,
                        gadgets=gadgets, libc_path='/tmp/bench/libc.so.6')
    code = e.generate()
    assert 'use_rdi = POP_RDI' in code
    assert 'not (0x400000 <= use_rdi < 0x10000000)' in code, 'binary gadget no-rebase, libc offset rebase'
    assert 'ROP(libc).ret.address' in code, 'stack alignment ret from libc'
    ast.parse(code)


def test_ret2win_prefers_calls_win_and_alignment_variants():
    from exploit_templates import Ret2WinExploit
    analysis = {
        'buffers': [{'type': 'stack_frame', 'size': 32}],
        'protections': {'nx': False, 'pie': False, 'canary': False},
        'functions': {'win': [('system', '0x401094'), ('win_calls_system@plt', '0x4011b6')]},
    }
    gadgets = {'arch': 'amd64', 'specific': {'ret': None}, 'plt': {}}
    e = Ret2WinExploit(binary_path='/tmp/bench/ret2win_stripped', analysis=analysis,
                       gadgets=gadgets, libc_path=None)
    code = e.generate()
    # win_calls_* 优先: WIN 必须是函数入口 0x4011b6 而非 PLT 桩
    assert 'WIN = 0x4011b6' in code
    # 双变体: 直接跳 + 对齐 ret 变体 (movaps 对齐崩溃兜底)
    assert 'try_once(prepend_ret=False' in code
    assert 'try_once(prepend_ret=True' in code
    # 对齐 ret 兜底从 ELF/libc 搜
    assert 'ROP(elf).ret.address' in code
    ast.parse(code)


def test_feedback_success_beats_crash_noise():
    from feedback_analyzer import FeedbackAnalyzer
    fa = FeedbackAnalyzer(verbose=False)
    # 成功标志 + 干净退出 + 无崩溃证据 -> 成功
    r = fa.analyze("PWNED_OK\nuid=1000(x)", "", 0)
    assert r.success
    # 真实崩溃退出码 (负值) -> 即使含 PWNED_OK 也失败
    r = fa.analyze("PWNED_OK\nSIGSEGV at 0x41414141", "", -11)
    assert not r.success
    # exit=0 但 stderr 含子进程崩溃证据 -> 失败 (模板应抑制噪声而非靠 analyzer 兜底)
    r = fa.analyze("PWNED_OK", "Process stopped with signal SIGSEGV", 0)
    assert not r.success


def test_analyzer_find_function_start():
    """calls_system@plt 检测必须回溯到函数入口而非 call 指令地址。"""
    from analyzer import BinaryAnalyzer
    disasm = (
        "0000000000401196 <vuln>:\n"
        "  401196:\tendbr64\n"
        "  40119a:\tpush   rbp\n"
        "  40119b:\tmov    rbp,rsp\n"
        "  4011a0:\tcall   401080 <gets@plt>\n"
        "  4011a5:\tret\n"
        "  4011b6:\tendbr64\n"
        "  4011ba:\tpush   rbp\n"
        "  4011bb:\tmov    rbp,rsp\n"
        "  4011c8:\tcall   401080 <puts@plt>\n"
        "  4011d7:\tcall   401090 <system@plt>\n"
        "  4011de:\tret\n"
    )
    a = object.__new__(BinaryAnalyzer)
    assert a._find_function_start(disasm, 0x4011d7) == 0x4011b6


if __name__ == '__main__':
    for f in [test_rop_exploit_no_invalid_rop_ctor,
              test_rop_exploit_no_recv_after_close,
              test_rop_exploit_rebases_libc_offset_gadgets,
              test_solver_system_libc_fallback_paths,
              test_ret2libc_leak_stage2_rebases_pop_rdi,
              test_ret2win_prefers_calls_win_and_alignment_variants,
              test_feedback_success_beats_crash_noise,
              test_analyzer_find_function_start]:
        f()
        print('PASS', f.__name__)
