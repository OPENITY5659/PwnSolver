#!/usr/bin/env python3
"""针对本轮优化 (P0/P1/P2) 的回归测试 — 不运行 exploit, 只验证检测与代码生成不变量"""
import sys
import os

BASE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.join(BASE, '..')
sys.path.insert(0, os.path.join(BASE, '..', 'pwn_solver'))

CHALLENGES = os.path.join(ROOT, 'challenges')


def test_auto_detect_libc_fallback():
    """本地题无同目录 libc 时 fallback 系统 libc (架构匹配)"""
    from badchars import auto_detect_libc
    libc = auto_detect_libc(os.path.join(CHALLENGES, 'ret2libc'))
    assert libc is not None, "应 fallback 到系统 libc"
    assert os.path.exists(libc)


def test_gadget_specific_binary_vs_libc_separation():
    """specific 只含 binary gadget; libc gadget 走 libc_ 前缀; PLT/GOT 引用齐全"""
    from gadget_finder import GadgetFinder
    from badchars import auto_detect_libc
    libc = auto_detect_libc(os.path.join(CHALLENGES, 'ret2libc'))
    gf = GadgetFinder(os.path.join(CHALLENGES, 'ret2libc'), libc, verbose=False)
    sp = gf.get_specific_gadgets()
    # ret2libc 教学题 (gcc14) 无 binary pop rdi
    assert sp['pop_rdi'] is None
    assert sp['libc_pop_rdi'], "libc 中应有 pop_rdi 相对偏移"
    assert sp['puts_plt'] and sp['puts_got'] and sp['gets_plt']
    assert sp['libc_pop_rdi'] < 0x1000000, "libc gadget 应是相对偏移"


def test_fmt_and_global_compare_detection():
    """fmtstr 题: printf(栈缓冲) + secret 比较检测"""
    from analyzer import BinaryAnalyzer
    a = BinaryAnalyzer(os.path.join(CHALLENGES, 'fmtstr'), verbose=False)
    f = a.find_interesting_functions()
    assert f['fmt_string']['fmt_string'] is True
    assert f['global_compare'], "应检测到 secret==0xdeadbeef 比较"
    assert f['global_compare'][0]['value'] == 0xdeadbeef


def test_heap_menu_fgets_atoi_detection():
    """heap_uaf: fgets+atoi 菜单题识别"""
    from analyzer import BinaryAnalyzer
    a = BinaryAnalyzer(os.path.join(CHALLENGES, 'heap_uaf'), verbose=False)
    f = a.find_interesting_functions()
    assert f['heap_menu']['heap_menu'] is True
    assert f['heap_menu']['input_style'] == 'fgets_atoi'


def test_no_fmt_false_positive_on_ret2libc():
    """ret2libc 无误报 fmt_string"""
    from analyzer import BinaryAnalyzer
    a = BinaryAnalyzer(os.path.join(CHALLENGES, 'ret2libc'), verbose=False)
    f = a.find_interesting_functions()
    assert not f['fmt_string']['fmt_string']


def _mk_analysis():
    return {
        'protections': {'pie': False, 'nx': True, 'canary': False},
        'functions': {
            'win': [], 'implied_win': [], 'dangerous': [('gets', '0x401094')],
            'has_binsh': True, 'fmt_string': {}, 'global_compare': [],
            'heap_menu': {}, 'inner_overflows': [],
        },
        'buffers': [{'type': 'stack_frame', 'size': 48}],
    }


def test_ret2win_system_plt_mode():
    """stripped: win=[system@plt] + binsh → 生成 system 模式 (pop_rdi+binsh+system)"""
    from exploit_templates import Ret2WinExploit
    analysis = _mk_analysis()
    analysis['functions']['win'] = [('system', '0x401094')]
    gadgets = {
        'specific': {'pop_rdi': None, 'libc_pop_rdi': 0x11bc7a, 'ret': None},
        'plt': {'system': 0x401094}, 'arch': 'amd64',
    }
    exp = Ret2WinExploit(binary_path=os.path.join(CHALLENGES, 'ret2win_stripped'),
                         analysis=analysis, gadgets=gadgets, libc_path=None,
                         verbose=False)
    code = exp.generate()
    assert "WIN_MODE = 'system'" in code
    compile(code, '<ret2win_system>', 'exec')


def test_ret2win_direct_mode_with_main_win():
    """有真 win 函数 → 直接跳转模式"""
    from exploit_templates import Ret2WinExploit
    analysis = _mk_analysis()
    analysis['functions']['win'] = [('win', '0x4011b6')]
    gadgets = {'specific': {'pop_rdi': 0x40120b, 'libc_pop_rdi': 0x11bc7a, 'ret': 0x40101a},
               'plt': {}, 'arch': 'amd64'}
    exp = Ret2WinExploit(binary_path=os.path.join(CHALLENGES, 'ret2win'),
                         analysis=analysis, gadgets=gadgets, libc_path=None,
                         verbose=False)
    code = exp.generate()
    assert "WIN_MODE = 'direct'" in code
    assert 'WIN = 0x4011b6' in code
    compile(code, '<ret2win_direct>', 'exec')


def test_ret2libc_no_poprdi_template_syntax():
    """无 pop_rdi 的 ret2libc 模板: 生成代码可编译且含对齐 ret"""
    from exploit_templates import Ret2LibcExploit
    from badchars import auto_detect_libc
    libc = auto_detect_libc(os.path.join(CHALLENGES, 'ret2libc'))
    analysis = _mk_analysis()
    analysis['functions']['win'] = []
    gadgets = {
        'specific': {'pop_rdi': None, 'libc_pop_rdi': 0x11bc7a, 'ret': None,
                     'libc_ret': 0x289fe, 'puts_plt': 0x401074, 'puts_got': 0x404000,
                     'write_plt': None, 'write_got': None},
        'pop_rdi_in_binary': False, 'plt': {'puts': 0x401074}, 'arch': 'amd64',
    }
    exp = Ret2LibcExploit(binary_path=os.path.join(CHALLENGES, 'ret2libc'),
                          analysis=analysis, gadgets=gadgets,
                          libc_path=libc, verbose=False)
    code = exp.generate()
    assert 'No pop_rdi gadget' in code
    assert 'p.libs()' in code
    compile(code, '<ret2libc_nopoprdi>', 'exec')


def test_ret2libc_with_poprdi_template_syntax():
    """有 pop_rdi 的 ret2libc 模板: leak 分支生成代码可编译"""
    from exploit_templates import Ret2LibcExploit
    from badchars import auto_detect_libc
    libc = auto_detect_libc(os.path.join(CHALLENGES, 'ret2libc'))
    analysis = _mk_analysis()
    gadgets = {
        'specific': {'pop_rdi': 0x40120b, 'libc_pop_rdi': 0x11bc7a, 'ret': 0x40101a,
                     'puts_plt': 0x401074, 'puts_got': 0x404000,
                     'write_plt': None, 'write_got': None},
        'pop_rdi_in_binary': True, 'plt': {'puts': 0x401074}, 'arch': 'amd64',
    }
    exp = Ret2LibcExploit(binary_path=os.path.join(CHALLENGES, 'ret2libc_final'),
                          analysis=analysis, gadgets=gadgets,
                          libc_path=libc, verbose=False)
    code = exp.generate()
    assert 'Stage 1: Leak puts' in code
    compile(code, '<ret2libc_poprdi>', 'exec')


def test_ret2libc_menu_scanf_leak_template_syntax():
    """pwn04 真实场景: scanf 菜单 + read 溢出 (有 pop_rdi) → leak 模板必须可编译

    回归: menu_prelude() 注入曾在 Stage2 的 8 空格上下文产生 4 空格行导致
    IndentationError (用户真实使用 pwn04 时发现)
    """
    from exploit_templates import Ret2LibcExploit
    from badchars import auto_detect_libc
    libc = auto_detect_libc(os.path.join(CHALLENGES, 'ret2libc'))
    analysis = _mk_analysis()
    analysis['functions']['input_stages'] = [
        {'type': 'scanf', 'size': 0, 'function': 'main', 'order': 0},
        {'type': 'read', 'size': 0x100, 'function': 'vuln', 'order': 1},
    ]
    gadgets = {
        'specific': {'pop_rdi': 0x40120b, 'libc_pop_rdi': 0x11bc7a, 'ret': 0x40101a,
                     'puts_plt': 0x401074, 'puts_got': 0x404000,
                     'write_plt': None, 'write_got': None},
        'pop_rdi_in_binary': True, 'plt': {'puts': 0x401074}, 'arch': 'amd64',
    }
    exp = Ret2LibcExploit(binary_path=os.path.join(CHALLENGES, 'ret2libc_final'),
                          analysis=analysis, gadgets=gadgets,
                          libc_path=libc, verbose=False)
    code = exp.generate()
    assert '菜单选择 (scanf 第一轮)' in code
    # 两个 stage 的菜单前置都注入
    assert code.count("p.sendline(b'1')  # 菜单选择") == 2
    compile(code, '<ret2libc_menu_scanf>', 'exec')


def test_fmtstr_template_syntax():
    """FormatStringExploit 模板: 目标注入 + 可编译"""
    from exploit_templates import FormatStringExploit
    analysis = _mk_analysis()
    analysis['functions']['global_compare'] = [{'addr': 0x40406c, 'value': 0xdeadbeef}]
    analysis['functions']['fmt_string'] = {'fmt_string': True, 'funcs': ['vuln']}
    gadgets = {
        'specific': {'puts_got': 0x404000, 'printf_got': 0x404008},
        'plt': {'printf': 0x401084}, 'arch': 'amd64',
    }
    exp = FormatStringExploit(binary_path=os.path.join(CHALLENGES, 'fmtstr'),
                              analysis=analysis, gadgets=gadgets,
                              libc_path=None, verbose=False)
    code = exp.generate()
    assert 'TARGET_ADDR = 0x40406c' in code
    assert 'fmtstr_payload' in code
    compile(code, '<fmtstr>', 'exec')


def test_zz955_gated_by_binary_segments():
    """Ret2SyscallExploit: s.s.a.l 专属地址在非 s.s.a.l binary 上被禁用"""
    from exploit_templates import Ret2SyscallExploit
    from badchars import auto_detect_libc
    libc = auto_detect_libc(os.path.join(CHALLENGES, 'ret2libc'))
    analysis = _mk_analysis()
    analysis['functions']['prng_info'] = {'prng_detected': True}
    gadgets = {
        'specific': {'pop_rax': 0x40120b, 'pop_rdi': 0x40120b, 'pop_rsi': 0x40120b,
                     'syscall': 0x40120b, 'ret': 0x40101a, 'libc_pop_rdi': 0x11bc7a},
        'pop_rdi_in_binary': True, 'plt': {}, 'arch': 'amd64',
    }
    exp = Ret2SyscallExploit(binary_path=os.path.join(CHALLENGES, 'ret2libc'),
                             analysis=analysis, gadgets=gadgets,
                             libc_path=libc, verbose=False)
    code = exp.generate()
    assert 'ZZ955_OK = False' in code, "0x400802/0x400834/0x601090 不在 ret2libc 段内, 必须禁用"
    compile(code, '<ret2syscall>', 'exec')


def test_one_gadget_template_syntax_both_branches():
    """OneGadgetExploit 两个分支 (有/无 pop_rdi) 生成代码均可编译

    回归: no-output 分支 (无 pop_rdi 时) 曾生成 IndentationError
    (用户真实使用 fmt1 时发现: if REMOTE_HOST 后缺缩进)
    """
    from exploit_templates import OneGadgetExploit
    from badchars import auto_detect_libc
    libc = auto_detect_libc(os.path.join(CHALLENGES, 'ret2libc'))
    base_gadgets = {
        'specific': {'pop_rdi': 0x40120b, 'libc_pop_rdi': 0x11bc7a, 'ret': 0x40101a,
                     'libc_ret': 0x289fe, 'puts_plt': 0x401074, 'puts_got': 0x404000},
        'pop_rdi_in_binary': True, 'plt': {'puts': 0x401074}, 'arch': 'amd64',
        'one_gadgets': [{'offset': '0xf8723', 'constraints': 'x'}],
    }
    # 分支 1: 有 pop_rdi (has_output) — fmt1 类似但 pop_rdi 存在
    exp = OneGadgetExploit(binary_path=os.path.join(CHALLENGES, 'ret2libc_final'),
                           analysis=_mk_analysis(), gadgets=base_gadgets,
                           libc_path=libc, verbose=False)
    code1 = exp.generate()
    compile(code1, '<one_gadget_with_poprdi>', 'exec')

    # 分支 2: 无 binary pop_rdi (no-output 分支) — fmt1 真实场景
    g2 = dict(base_gadgets)
    g2['specific'] = dict(base_gadgets['specific'], pop_rdi=None)
    g2['pop_rdi_in_binary'] = False
    exp2 = OneGadgetExploit(binary_path=os.path.join(CHALLENGES, 'ret2libc'),
                            analysis=_mk_analysis(), gadgets=g2,
                            libc_path=libc, verbose=False)
    code2 = exp2.generate()
    assert 'No output functions' in code2 or 'one_gadget' in code2
    compile(code2, '<one_gadget_no_poprdi>', 'exec')


def test_io_leak_detection_canary_and_pie():
    """read+write 栈泄露模式检测: canary 题 (rbp帧) 与 scanf型全防护题 (调用者帧)"""
    from analyzer import BinaryAnalyzer
    a = BinaryAnalyzer(os.path.join(CHALLENGES, 'ret2libc_canary'), verbose=False)
    f = a.find_interesting_functions()
    il = f['io_leak']
    assert il['io_leak'] is True
    assert il['style'] == 'read_write'
    assert il['dist_canary'] == 56 and il['dist_ret'] == 72
    assert il['frame_mode'] == 'rbp'
    assert il['anchor'] == 'call_vuln'

    a2 = BinaryAnalyzer(os.path.join(CHALLENGES, 'ret2libc_allprot'), verbose=False)
    f2 = a2.find_interesting_functions()
    il2 = f2['io_leak']
    assert il2['io_leak'] is True
    assert il2['style'] == 'scanf_size_read'
    assert il2['dist_ret'] == 88 and il2['dist_canary'] == 56
    assert il2['frame_mode'] == 'rsp'
    assert il2['anchor'] == 'main_ret'


def test_hardened_template_syntax():
    """Ret2LibcHardenedExploit 模板: 参数注入 + 生成代码可编译"""
    from exploit_templates import Ret2LibcHardenedExploit
    analysis = _mk_analysis()
    analysis['functions']['io_leak'] = {
        'io_leak': True, 'style': 'read_write', 'scanf_size': False,
        'dist_canary': 56, 'dist_ret': 72, 'frame_mode': 'rbp',
        'call_vuln_ret_off': 0x12b0, 'anchor': 'call_vuln',
    }
    gadgets = {
        'specific': {'pop_rdi': None, 'libc_pop_rdi': 0x11bc7a, 'ret': 0x40101a,
                     'libc_ret': 0x289fe, 'puts_plt': 0x401074, 'puts_got': 0x404000},
        'pop_rdi_in_binary': False, 'plt': {'puts': 0x401074}, 'arch': 'amd64',
    }
    exp = Ret2LibcHardenedExploit(binary_path=os.path.join(CHALLENGES, 'ret2libc_canary'),
                                  analysis=analysis, gadgets=gadgets,
                                  libc_path=None, verbose=False)
    code = exp.generate()
    assert 'DIST_CANARY = 56' in code
    assert 'DIST_RET = 72' in code
    assert "ANCHOR = 'call_vuln'" in code
    compile(code, '<hardened>', 'exec')


if __name__ == '__main__':
    for fn in sorted(k for k in list(globals()) if k.startswith('test_')):
        print(f"--- {fn}")
        globals()[fn]()
        print("    OK")
    print("\n=== all regression tests passed ===")
