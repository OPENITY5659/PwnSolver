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


## 预构建镜像（GitHub Release）

网络不适合构建时，可直接下载已打包镜像：

```bash
gh release download v0.1.0-x86-image -R OPENITY5659/PwnSolver -p pwnsolver-x86.tar.zst
scripts/load-x86-image.sh ./pwnsolver-x86.tar.zst
```

> Docker Hub/GHCR 推送需要额外 token scope；当前采用 GitHub Release 分发
> `docker save | zstd` 归档，不需要 registry。


## 镜像发布方式

- 推荐：GitHub Actions workflow `.github/workflows/publish-x86-image.yml`
  推送到 `ghcr.io/<owner>/pwnsolver-x86:latest`；若配置 `DOCKERHUB_USERNAME/DOCKERHUB_TOKEN`
  可同时推 Docker Hub。
- 免构建：GitHub Release `v0.1.0-x86-image` 提供 `docker save | zstd` 归档，
  使用 `scripts/load-x86-image.sh` 导入。
