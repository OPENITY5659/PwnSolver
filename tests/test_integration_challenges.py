#!/usr/bin/env python3
"""端到端集成测试 — 实际运行二进制程序, 验证 solver 对不同提示风格与多轮输入的自动解题能力。

默认跳过 (需显式启用, 每道题约 2-10s):
    RUN_INTEGRATION=1 python -m pytest tests/test_integration_challenges.py -q
或
    RUN_INTEGRATION=1 python tests/test_integration_challenges.py
"""
import os
import sys
import subprocess

import pytest

BASE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.join(BASE, '..')
CHALLENGES = os.path.join(ROOT, 'challenges')
SOLVER = os.path.join(ROOT, 'pwn_solver', 'solver.py')

# (题目名, 说明, 覆盖的交互特性)
CASES = [
    ('ret2win_prompt', '自定义提示文本 ("Please enter your name: ") + gets 溢出'),
    ('two_stage',    '多轮输入: scanf 菜单选择 -> gets 溢出 (ret2libc)'),
    ('loop_menu',    '多轮循环菜单 ("cmd> ") + 格式化字符串 (写 secret 触发 win)'),
    ('fmtstr',       '经典 fmtstr: printf(buf) 写 secret'),
    ('ret2libc',     '经典 ret2libc 秒杀路径'),
    ('ret2win',      '经典 ret2win'),
    ('ret2libc_canary', 'canary 绕过 (write 长度泄露)'),
    ('ret2libc_allprot', '全防护绕过 (canary+PIE+Full RELRO+FORTIFY, scanf 型)'),
]

INTEGRATION_ENABLED = os.environ.get('RUN_INTEGRATION') == '1'

pytestmark = pytest.mark.skipif(
    not INTEGRATION_ENABLED,
    reason="端到端集成测试默认跳过; 用 RUN_INTEGRATION=1 启用"
)


def run_solver(name, timeout=150):
    bin_path = os.path.join(CHALLENGES, name)
    if not os.path.exists(bin_path):
        raise RuntimeError(f"缺少二进制 {bin_path} — 先编译 challenges/{name}.c")
    cmd = [sys.executable, SOLVER, bin_path, '-t', '10', '-q']
    r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    return r


@pytest.mark.parametrize('name,desc', CASES, ids=[c[0] for c in CASES])
def test_solver_solves_challenge(name, desc):
    """实际跑程序 → solver 自动解题 (覆盖不同提示与多轮输入)"""
    r = run_solver(name)
    assert r.returncode == 0, (
        f"[{name}] ({desc}) solver 失败:\n"
        f"--- stdout tail ---\n{r.stdout[-800:]}\n"
        f"--- stderr tail ---\n{r.stderr[-400:]}"
    )


if __name__ == '__main__':
    if not INTEGRATION_ENABLED:
        print("RUN_INTEGRATION 未设置 — 默认跳过。启用: RUN_INTEGRATION=1 python tests/test_integration_challenges.py")
        sys.exit(0)
    failed = []
    for name, desc in CASES:
        print(f"--- [{name}] {desc}")
        try:
            r = run_solver(name)
            if r.returncode == 0:
                print(f"    PASS")
            else:
                failed.append(name)
                print(f"    FAIL (exit={r.returncode})")
                print(r.stdout[-500:])
        except Exception as e:
            failed.append(name)
            print(f"    ERROR: {e}")
    print(f"\n=== {len(CASES) - len(failed)}/{len(CASES)} 通过 ===")
    sys.exit(1 if failed else 0)
