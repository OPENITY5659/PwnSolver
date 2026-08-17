#!/usr/bin/env python3
"""pytest-based verification of pwn_solver improvements."""
import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'pwn_solver'))

def test_analyzer_new_methods():
    from analyzer import BinaryAnalyzer
    assert hasattr(BinaryAnalyzer, '_detect_array_overflow')
    assert hasattr(BinaryAnalyzer, '_detect_prng_usage')
    assert hasattr(BinaryAnalyzer, '_detect_go_binary')
    assert hasattr(BinaryAnalyzer, '_detect_stack_pivot')

def test_gadget_finder_new_methods():
    from gadget_finder import GadgetFinder
    assert hasattr(GadgetFinder, 'find_xor_gadgets')
    assert hasattr(GadgetFinder, 'find_setcontext_gadget')
    assert hasattr(GadgetFinder, 'find_register_clearing_gadgets')
    assert hasattr(GadgetFinder, 'find_pop_rsi_rdi_gadget')
    assert hasattr(GadgetFinder, 'generate_ret2syscall_chain')

def test_orw_engine_new_methods():
    from orw_engine import ORWEngine, CombinedStrategyEngine
    assert hasattr(ORWEngine, 'generate_setcontext_orw_chain')
    assert hasattr(CombinedStrategyEngine, '_try_setcontext_orw')
    assert hasattr(CombinedStrategyEngine, '_try_ret2syscall')

def test_bruteforcer_new_methods():
    from bruteforcer import BruteForcer
    assert hasattr(BruteForcer, 'brute_prng_seed')
    assert hasattr(BruteForcer, 'brute_one_gadget_with_constraints')

def test_heap_exploit_exists():
    from heap_exploit import HeapExploitEngine
    assert hasattr(HeapExploitEngine, 'tcache_poison_attack')
    assert hasattr(HeapExploitEngine, 'rtld_global_hijack')
    assert hasattr(HeapExploitEngine, 'unsorted_bin_attack')
    assert hasattr(HeapExploitEngine, '_build_fake_link_map')

def test_solver_imports():
    from solver import PwnSolver
    assert PwnSolver is not None

def test_ciscn_specialized_exploits():
    from exploit_templates import GoStackExploit, OrangeCatDiaryExploit
    assert GoStackExploit.KNOWN_PARAMS['offset'] == 0x1d0
    assert OrangeCatDiaryExploit.COMPAT_LD.endswith('ld-2.23.so')
    assert 0xf03a4 in OrangeCatDiaryExploit.ONE_GADGETS

def test_pattern_engine_ciscn_overlays():
    from pattern_engine import PatternEngine, PatternMatch
    assert 'go_stack_overflow' in PatternEngine.VULN_MAP
    assert PatternEngine.VULN_MAP['go_stack_overflow'] == 'go_stack'
    assert PatternEngine.VULN_MAP.get('orange_cat_diary') == 'orange_cat'
    assert issubclass(PatternMatch, object)

def test_feedback_analyzer():
    from feedback_analyzer import FeedbackAnalyzer, FeedbackResult, ErrorType, AdjustmentSuggestion
    fa = FeedbackAnalyzer(verbose=False)
    # segfault
    r = fa.analyze("SIGSEGV at 0x7f4141414141", "", -11)
    assert r.error_type == ErrorType.SEGFAULT
    assert r.crash_addr == 0x7f4141414141
    # success (需 clean exit)
    r = fa.analyze("PWNED_OK", "", 0)
    assert r.success
    # SIGSEGV 输出包含 "PWNED_OK" 但 exit_code=-11 → 不应判定成功
    r = fa.analyze("PWNED_OK\nSIGSEGV at 0x41414141", "", -11)
    assert not r.success, "SIGSEGV with -11 must NOT be success"
    assert r.error_type == ErrorType.SEGFAULT
    # 漏洞exp退出码0但子进程崩溃 → crash证据应阻止成功判定
    r = fa.analyze("PWNED_OK", "Process stopped with signal SIGSEGV", 0)
    assert not r.success, "child crash evidence must block success even with exit_code=0"
    # SIGILL
    r = fa.analyze("Program received signal SIGILL\n0x00007f1234", "", -4)
    assert r.error_type == ErrorType.INVALID_INSTRUCTION
    # timeout flag
    r = fa.analyze("", "", None, timeout=True)
    assert r.error_type == ErrorType.TIMEOUT

def test_adaptive_solver_imports():
    from adaptive_solver import AdaptiveSolver, AdaptiveConfig, AttemptRecord
    assert AdaptiveSolver is not None
    assert AdaptiveConfig is not None

def test_multi_stage_leak_imports():
    from multi_stage_leak import MultiStageLeakEngine, LeakStep, MultiStagePlan, LeakKind
    assert MultiStageLeakEngine is not None
    assert LeakKind.STACK_ADDR is not None

def test_feedback_integration():
    """验证 exploit_templates 已支持 test_with_feedback"""
    from exploit_templates import BaseExploit
    assert hasattr(BaseExploit, 'test_with_feedback'), "Missing test_with_feedback"


def test_pop_rsi_rdi_prefers_exact_gadget():
    """ROPgadget 会输出前置 add/nop 的伪 gadget；必须优先精确 pop rsi; pop rdi; ret。"""
    from gadget_finder import GadgetFinder
    gf = GadgetFinder.__new__(GadgetFinder)
    gf._cache = {
        'rop_gadgets': [
            '0x40082f : add bl, al ; pop rsi ; pop rdi ; ret',
            '0x400961 : pop rsi ; pop r15 ; ret',
            '0x400831 : pop rsi ; pop rdi ; ret',
        ],
        'libc_rop_gadgets': [],
    }
    gf.libc = None
    assert gf.find_pop_rsi_rdi_gadget() == 0x400831


def test_badboy_exploit_template_compiles():
    from exploit_templates import BadBoyArrayOOBExploit
    import tempfile, os
    with tempfile.TemporaryDirectory() as tmp:
        dummy = os.path.join(tmp, "dummy")
        with open(dummy, "wb") as f:
            f.write(b"\x7fELF")
        code = BadBoyArrayOOBExploit(
            binary_path=dummy, libc_path=None,
            analysis={}, gadgets={'arch': 'amd64'}, verbose=False,
        ).generate()
        compile(code, "<BadBoyArrayOOBExploit>", "exec")


def test_generated_exploit_templates_are_syntactically_valid():
    """reverse-skill pwn-chain 约束: 生成的 exploit 必须是可执行代码。"""
    import tempfile
    import os
    from exploit_templates import (
        OneGadgetExploit,
        StackPivotExploit,
        Ret2LibcExploit,
        YesOrNoExploit,
    )

    with tempfile.TemporaryDirectory() as tmp:
        dummy = os.path.join(tmp, "dummy")
        with open(dummy, "wb") as f:
            f.write(b"\x7fELF")

        analysis = {
            "info": {"type": "ELF", "arch": "amd64", "bits": 64},
            "protections": {"nx": True, "pie": False, "canary": False, "relro": False},
            "functions": {
                "dangerous": [("gets", "0x401000")],
                "win": [],
                "main": 0x401200,
            },
            "buffers": [{"type": "stack_frame", "size": 48}],
        }
        # 特意模拟“binary 无 pop_rdi”的分支，历史上生成过 IndentationError
        gadgets = {
            "arch": "amd64",
            "specific": {"pop_rdi": None, "ret": 0x401301},
            "plt": {"puts": "0x401030"},
            "one_gadgets": [{"offset": "0x583dc", "constraints": "posix_spawn"}],
        }

        for cls in (Ret2LibcExploit, OneGadgetExploit, StackPivotExploit, YesOrNoExploit):
            code = cls(
                binary_path=dummy,
                libc_path=None,
                analysis=analysis,
                gadgets=gadgets,
                verbose=False,
            ).generate()
            compile(code, f"<{cls.__name__}>", "exec")
