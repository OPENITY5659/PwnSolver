#!/usr/bin/env python3
"""
工具函数
"""

import os
import sys
import subprocess


def run_command(cmd, timeout=30, cwd=None):
    """运行命令并返回输出"""
    try:
        result = subprocess.run(
            cmd, capture_output=True, text=True, timeout=timeout, cwd=cwd
        )
        return result.stdout, result.stderr, result.returncode
    except subprocess.TimeoutExpired:
        return "", "Timeout", -1
    except Exception as e:
        return "", str(e), -1


def ensure_wsl_path(path):
    """将Windows路径转换为WSL路径"""
    if sys.platform == 'win32':
        # Windows路径 -> /mnt/c/Users/...
        path = path.replace('\\', '/')
        if ':' in path:
            drive, rest = path.split(':', 1)
            path = f'/mnt/{drive.lower()}{rest}'
    return path


def find_libc():
    """尝试找到系统libc"""
    candidates = [
        '/lib/x86_64-linux-gnu/libc.so.6',
        '/lib/i386-linux-gnu/libc.so.6',
        '/lib/x86_64-linux-gnu/libc-*.so',
        '/usr/lib/x86_64-linux-gnu/libc.so.6',
        '/lib/aarch64-linux-gnu/libc.so.6',
    ]
    
    import glob
    for pattern in candidates:
        matches = glob.glob(pattern)
        if matches:
            return matches[0]
    
    # 使用ldd查找
    try:
        result = subprocess.run(
            ['ldd', '/bin/ls'], capture_output=True, text=True, timeout=5
        )
        for line in result.stdout.split('\n'):
            if 'libc.so' in line:
                # 提取路径
                import re
                m = re.search(r'(/\S+)', line)
                if m:
                    return m.group(1)
    except Exception:
        pass
    
    return None


def check_tools():
    """检查必要工具"""
    tools = {
        'ROPgadget': ['ROPgadget', '--version'],
        'one_gadget': ['one_gadget', '--version'],
        'gdb': ['gdb', '--version'],
        'objdump': ['objdump', '--version'],
        'strings': ['strings', '--version'],
    }
    
    results = {}
    for name, cmd in tools.items():
        stdout, stderr, rc = run_command(cmd)
        results[name] = rc == 0
    
    return results
