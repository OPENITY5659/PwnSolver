#!/usr/bin/env python3
"""轻量反编译器 (伪 C / F5 风格) 测试"""
import os
import sys

BASE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.join(BASE, '..')
sys.path.insert(0, os.path.join(BASE, '..', 'pwn_solver'))
sys.path.insert(0, ROOT)

from decompiler import decompile, parse_objdump

CHALLENGES = os.path.join(ROOT, 'challenges')


def test_parse_objdump():
    funcs = parse_objdump(os.path.join(CHALLENGES, 'ret2win'))
    assert 'main' in funcs and 'vuln' in funcs
    assert funcs['main'][0][1]  # 有指令


def test_decompile_ret2win_pseudo_c():
    text, annot = decompile(os.path.join(CHALLENGES, 'ret2win'))
    # main 与调用链内用户函数
    assert 'void main()' in text
    assert 'void vuln()' in text
    # win 函数强制显示 (解题目标, 即使不在调用链)
    assert 'void win()' in text
    assert 'system("/bin/sh")' in text
    # plt 调用不展开 (只有调用行)
    assert 'gets(buf)' in text
    assert '!危险调用' in text
    assert '@plt' not in text
    # 字符串字面量
    assert 'Enter your name:' in text
    # 标注存在
    assert any(t == 'danger_call' for t in annot.values())


def test_decompile_two_stage_menu():
    """多轮输入题: 菜单 scanf 危险标注 + 两阶段函数"""
    text, annot = decompile(os.path.join(CHALLENGES, 'two_stage'))
    assert 'void main()' in text
    assert 'void vuln()' in text
    assert '__isoc23_scanf' in text or 'scanf' in text
    assert any(t == 'danger_call' for t in annot.values())


def test_decompile_no_libc_expansion():
    """libc 等动态链接函数不展开: 无 _start/libc 内部函数"""
    text, annot = decompile(os.path.join(CHALLENGES, 'ret2libc'))
    assert 'void main()' in text
    # 不会展开 libc 内部函数 (如 __libc_start_main 本体)
    assert 'void __libc' not in text
    assert 'void _start' not in text


if __name__ == '__main__':
    for fn in sorted(k for k in list(globals()) if k.startswith('test_')):
        print(f"--- {fn}")
        globals()[fn]()
        print("    OK")
    print("\n=== all decompiler tests passed ===")
