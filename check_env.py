#!/usr/bin/env python3
"""检查pwn解题环境"""
import sys

def check():
    results = []
    
    # pwntools
    try:
        from pwn import ELF, process, context
        results.append(("pwntools", True, f"可用 (arch={context.arch})"))
    except Exception as e:
        results.append(("pwntools", False, str(e)))
    
    # ROPgadget
    try:
        from ropgadget.core import Core
        results.append(("ROPgadget", True, "可用"))
    except Exception as e:
        results.append(("ROPgadget", False, str(e)))
    
    # capstone
    try:
        import capstone
        results.append(("capstone", True, f"v{capstone.__version__}"))
    except Exception as e:
        results.append(("capstone", False, str(e)))
    
    # unicorn
    try:
        import unicorn
        results.append(("unicorn", True, "可用"))
    except Exception as e:
        results.append(("unicorn", False, str(e)))
    
    # one_gadget (通过命令行)
    import subprocess
    try:
        r = subprocess.run(["one_gadget", "--version"], capture_output=True, text=True, timeout=10)
        results.append(("one_gadget", True, r.stdout.strip() or r.stderr.strip()))
    except Exception as e:
        results.append(("one_gadget", False, str(e)))
    
    # gdb
    try:
        r = subprocess.run(["gdb", "--version"], capture_output=True, text=True, timeout=10)
        first_line = r.stdout.strip().split('\n')[0]
        results.append(("gdb", True, first_line))
    except Exception as e:
        results.append(("gdb", False, str(e)))

    # radare2 / rabin2（reverse-skill DeepRecon 使用）
    import shutil
    rabin2 = shutil.which("rabin2")
    results.append(("radare2/rabin2", bool(rabin2), rabin2 or "未安装 (容器: scripts/pwn-x86)"))

    # reverse-skill 知识库
    try:
        import os
        root = os.path.join(os.path.dirname(os.path.abspath(__file__)), "reverse_skill")
        skills = [p.parent.name for p in __import__("pathlib").Path(root).rglob("SKILL.md")]
        results.append(("reverse-skill 知识库", bool(skills), f"{len(skills)} 个 skill 已集成"))
    except Exception as e:
        results.append(("reverse-skill 知识库", False, str(e)))

    # x86_64 容器（Apple Silicon 宿主机上的 PWN 沙盒）
    import platform as _platform
    if _platform.system() == "Darwin" and _platform.machine().lower() in ("arm64", "aarch64"):
        try:
            r = subprocess.run(["docker", "image", "inspect", "pwnsolver-x86:latest"],
                               capture_output=True, text=True, timeout=15)
            results.append(("x86_64 解题容器", r.returncode == 0,
                            "pwnsolver-x86:latest" if r.returncode == 0 else "镜像未构建 (scripts/pwn-x86-build)"))
        except Exception as e:
            results.append(("x86_64 解题容器", False, str(e)))
    
    print("=" * 60)
    print("PWN 解题环境检查")
    print("=" * 60)
    for name, ok, detail in results:
        status = "✓" if ok else "✗"
        print(f"  [{status}] {name}: {detail}")
    print("=" * 60)
    all_ok = all(r[1] for r in results)
    print(f"总体状态: {'✓ 全部就绪' if all_ok else '✗ 部分缺失'}")
    return all_ok

if __name__ == "__main__":
    ok = check()
    sys.exit(0 if ok else 1)
