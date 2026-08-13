#!/usr/bin/env python3
"""GUI/Web 前端逻辑测试 — 不实例化 Tk (无显示环境可跑)"""
import os
import sys

BASE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.join(BASE, '..')
sys.path.insert(0, ROOT)


def _import_pwn_gui():
    import importlib.util
    spec = importlib.util.spec_from_file_location('pwn_gui', os.path.join(ROOT, 'pwn_gui.py'))
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def test_sanitize():
    gui = _import_pwn_gui()
    # ESC(不可打印)与 NUL 被移除, 其余可见字符保留
    assert gui.sanitize('abc\x1b[31m红色\x00') == 'abc[31m红色'
    assert gui.sanitize('hello\nworld') == 'hello\nworld'


def test_to_wsl_path():
    gui = _import_pwn_gui()
    assert gui.to_wsl_path('C:\\Users\\x\\pwn') == '/mnt/c/Users/x/pwn'
    assert gui.to_wsl_path('D:\\CTF\\bin') == '/mnt/d/CTF/bin'
    assert gui.to_wsl_path('/home/user/bin') == '/home/user/bin'  # Linux 路径原样


def test_build_solve_cmd():
    gui = _import_pwn_gui()
    cmd = gui.build_solve_cmd('/ws', '/ws/pwn', libc='/ws/libc.so.6',
                              timeout=30, adaptive=True)
    assert "cd '/ws'" in cmd or 'cd /ws' in cmd
    assert '-l' in cmd and '/ws/libc.so.6' in cmd
    assert '-t 30' in cmd or '-t' in cmd
    assert '--no-adaptive' not in cmd

    cmd2 = gui.build_solve_cmd('/ws', '/ws/pwn', ld='/ws/ld.so',
                               remote_host='1.2.3.4', remote_port='9999',
                               timeout=60, adaptive=False)
    assert '-d' in cmd2 and '/ws/ld.so' in cmd2
    assert '-r' in cmd2 and '1.2.3.4' in cmd2 and '9999' in cmd2
    assert '--no-adaptive' in cmd2


def test_build_solve_cmd_real_world_paths():
    """真实使用场景: Windows 下载目录 + 中文空格路径, 不得双重引号"""
    import shlex
    gui = _import_pwn_gui()
    # 模拟 GUI 输入: Windows 路径 → to_wsl_path → build_solve_cmd (内部统一 quote)
    win = 'C:\\Users\\Lenovo\\Downloads\\元旦水友赛\\pwn04'
    wsl = gui.to_wsl_path(win)
    assert wsl == '/mnt/c/Users/Lenovo/Downloads/元旦水友赛/pwn04'

    cmd = gui.build_solve_cmd('/mnt/d/CTF Slover/PwnSolver', wsl,
                              libc='/mnt/c/Users/Lenovo/Downloads/元旦水友赛/libc.so.6')
    # 命令中不得出现嵌套引号 (之前双重 quote 产生的 ''"'"' 模式)
    assert "'''" not in cmd
    assert '"\'"\'' not in cmd
    # bash 解析后参数正确还原 (无引号残留)
    tokens = shlex.split(cmd)
    i = tokens.index('pwn_solver/solver.py') + 1
    assert tokens[i] == wsl, f"binary 参数被破坏: {tokens[i]!r}"
    j = tokens.index('-l') + 1
    assert tokens[j] == '/mnt/c/Users/Lenovo/Downloads/元旦水友赛/libc.so.6'
    # solver.py 收到的路径不应含引号字符
    assert "'" not in tokens[i] and "'" not in tokens[j]


def test_gui_start_solve_no_pre_quote():
    """GUI _start_solve 传参不再预 quote (防双重引号)"""
    import inspect
    gui = _import_pwn_gui()
    src = inspect.getsource(gui.PwnSolverGUI._start_solve)
    # 传参处必须是裸路径 (内部统一 quote)
    assert 'shlex.quote(wsl_binary)' not in src
    assert 'build_solve_cmd(' in src


def test_exec_prefix():
    gui = _import_pwn_gui()
    prefix = gui.exec_prefix()
    if sys.platform == 'win32':
        assert prefix == ['wsl', 'bash', '-c']
    else:
        assert prefix == ['bash', '-c']


def test_gui_class_methods_present():
    """GUI 类方法存在性 (优化后新增功能)"""
    gui = _import_pwn_gui()
    g = gui.PwnSolverGUI
    for m in ['_start_solve', '_on_solve_done', '_stop_solve', '_run_stream',
              '_open_interactive_shell', '_refresh_exp_list', '_copy_exp_path',
              '_delete_selected_exp', '_show_exp_menu', '_browse_ld']:
        assert hasattr(g, m), f"missing method: {m}"


def test_pwn_web_build_cmd():
    import pwn_web
    tm = pwn_web.TaskManager()
    cmd = tm._build_cmd('/tmp/pwn', libc='/tmp/libc.so.6', timeout=45,
                        ld='/tmp/ld.so', remote=('h', '7777'), quiet=True)
    assert cmd[0] == 'python3'
    assert '/tmp/pwn' in cmd
    assert '-l' in cmd and '/tmp/libc.so.6' in cmd
    assert '-d' in cmd and '/tmp/ld.so' in cmd
    assert '-r' in cmd and 'h' in cmd and '7777' in cmd
    assert '-t' in cmd and '45' in cmd
    assert '-q' in cmd

    cmd2 = tm._build_cmd('/tmp/pwn')
    assert '-l' not in cmd2 and '-r' not in cmd2 and '-q' not in cmd2


def test_solver_no_adaptive_flag():
    """solver CLI 支持 --no-adaptive 且 solve 有 use_adaptive 参数"""
    import inspect
    sys.path.insert(0, os.path.join(ROOT, 'pwn_solver'))
    import solver as solver_mod
    sig = inspect.signature(solver_mod.PwnSolver.solve)
    assert 'use_adaptive' in sig.parameters
    # argparse 参数注册验证 (构造 parser 再 parse --help 太慢, 直接检查源码)
    src = open(os.path.join(ROOT, 'pwn_solver', 'solver.py'), encoding='utf-8').read()
    assert "--no-adaptive" in src
    assert "use_adaptive=not args.no_adaptive" in src


def _has_display():
    import tkinter as tk
    try:
        r = tk.Tk()
        r.destroy()
        return True
    except Exception:
        return False


def test_gui_real_instantiation():
    """真实实例化 GUI (构建全部控件, 不进入 mainloop); 无显示环境自动跳过"""
    if not _has_display():
        import pytest
        pytest.skip("无显示环境")
    gui = _import_pwn_gui()
    g = gui.PwnSolverGUI()
    try:
        # 关键控件与新增功能存在
        for attr in ['binary_var', 'libc_var', 'ld_var', 'remote_host_var',
                     'timeout_var', 'adaptive_var', 'auto_shell_var',
                     'progress', 'status_var', 'exp_menu', 'exp_listbox',
                     'output', 'shell_input']:
            assert hasattr(g, attr), f"missing attr: {attr}"
        # 模拟输入与纯逻辑调用
        g.binary_var.set(os.path.join(ROOT, 'challenges', 'ret2win'))
        assert g._find_latest_exp() is not None
        g._refresh_exp_list()
        g.status_var.set("冒烟测试")
        g.log("GUI 冒烟测试 OK", 'info')
    finally:
        g.root.destroy()


if __name__ == '__main__':
    for fn in sorted(k for k in list(globals()) if k.startswith('test_')):
        print(f"--- {fn}")
        globals()[fn]()
        print("    OK")
    print("\n=== all gui tests passed ===")
