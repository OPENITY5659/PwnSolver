# x86_64 解题容器

Apple Silicon (M4) 宿主机上，绝大多数 CTF PWN 题是 x86/x86_64 ELF，直接用 arm64 的
pwntools/GDB 运行会失败。`docker/pwn-x86.Dockerfile` 通过 OrbStack 的 `--platform linux/amd64`
构建一个完整的 amd64 Ubuntu 解题环境（22.04 基础 + noble radare2/libc 2.39）：

- pwntools / ROPGadget / Ropper / capstone / unicorn / z3-solver / LibcSearcher
- gdb + GEF + gdbserver + strace / ltrace
- one_gadget + seccomp-tools
- radare2 (rabin2/r2)
- gcc / gcc-multilib（本地编译 i386 与 amd64 测试题）
- patchelf + libc-database 骨架

## 快速开始

```bash
# 构建镜像（首次使用）
scripts/pwn-x86-build

# 进入容器 bash（仓库根目录挂载在 /pwnsolver，当前目录挂载在 /ctf）
scripts/pwn-x86

# 在容器中运行 PwnSolver
scripts/pwn-x86 python3 /pwnsolver/pwn_solver/solver.py /ctf/vuln --recon-only

# 直接求解
scripts/pwn-x86 bash -lc "cd /ctf && python3 /pwnsolver/pwn_solver/solver.py ./vuln -l ./libc.so.6"
```

## 手工构建

```bash
docker build --platform linux/amd64 -t pwnsolver-x86:latest -f docker/pwn-x86.Dockerfile .
docker run --platform linux/amd64 --rm -it -v "$PWD:/work" -w /work pwnsolver-x86:latest
```
