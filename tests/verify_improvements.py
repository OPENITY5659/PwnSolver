#!/usr/bin/env python3
"""Verify all pwn_solver modules import and have expected methods."""
import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'pwn_solver'))

def test_analyzer():
    from analyzer import BinaryAnalyzer
    # Check new methods exist
    assert hasattr(BinaryAnalyzer, '_detect_array_overflow'), "Missing _detect_array_overflow"
    assert hasattr(BinaryAnalyzer, '_detect_prng_usage'), "Missing _detect_prng_usage"
    assert hasattr(BinaryAnalyzer, '_detect_go_binary'), "Missing _detect_go_binary"
    assert hasattr(BinaryAnalyzer, '_detect_stack_pivot'), "Missing _detect_stack_pivot"
    print("  analyzer: all 4 new methods present")

def test_gadget_finder():
    from gadget_finder import GadgetFinder
    assert hasattr(GadgetFinder, 'find_xor_gadgets'), "Missing find_xor_gadgets"
    assert hasattr(GadgetFinder, 'find_setcontext_gadget'), "Missing find_setcontext_gadget"
    assert hasattr(GadgetFinder, 'find_register_clearing_gadgets'), "Missing find_register_clearing_gadgets"
    assert hasattr(GadgetFinder, 'find_pop_rsi_rdi_gadget'), "Missing find_pop_rsi_rdi_gadget"
    assert hasattr(GadgetFinder, 'generate_ret2syscall_chain'), "Missing generate_ret2syscall_chain"
    print("  gadget_finder: all 5 new methods present")

def test_orw_engine():
    from orw_engine import ORWEngine, CombinedStrategyEngine
    assert hasattr(ORWEngine, 'generate_setcontext_orw_chain'), "Missing generate_setcontext_orw_chain"
    assert hasattr(CombinedStrategyEngine, '_try_setcontext_orw'), "Missing _try_setcontext_orw"
    assert hasattr(CombinedStrategyEngine, '_try_ret2syscall'), "Missing _try_ret2syscall"
    print("  orw_engine: all new methods present")

def test_bruteforcer():
    from bruteforcer import BruteForcer
    assert hasattr(BruteForcer, 'brute_prng_seed'), "Missing brute_prng_seed"
    assert hasattr(BruteForcer, 'brute_one_gadget_with_constraints'), "Missing brute_one_gadget_with_constraints"
    print("  bruteforcer: all 2 new methods present")

def test_heap_exploit():
    from heap_exploit import HeapExploitEngine
    assert hasattr(HeapExploitEngine, 'tcache_poison_attack'), "Missing tcache_poison_attack"
    assert hasattr(HeapExploitEngine, 'rtld_global_hijack'), "Missing rtld_global_hijack"
    assert hasattr(HeapExploitEngine, 'unsorted_bin_attack'), "Missing unsorted_bin_attack"
    assert hasattr(HeapExploitEngine, '_build_fake_link_map'), "Missing _build_fake_link_map"
    print("  heap_exploit: all methods present")

def test_solver():
    from solver import PwnSolver
    print("  solver: imports OK")

if __name__ == '__main__':
    print("Verifying pwn_solver modules...")
    test_analyzer()
    test_gadget_finder()
    test_orw_engine()
    test_bruteforcer()
    test_heap_exploit()
    test_solver()
    print()
    print("=== All verifications passed ===")
