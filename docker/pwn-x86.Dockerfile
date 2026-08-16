# syntax=docker/dockerfile:1
# PwnSolver x86_64 Linux 解题环境（适用于 Apple Silicon + OrbStack）
#
# 构建:
#   docker build --platform linux/amd64 -t pwnsolver-x86:latest -f docker/pwn-x86.Dockerfile .
# 或直接使用仓库脚本:
#   scripts/pwn-x86-build
#
# 可选：已有预装 radare2 的本地基础镜像时，可加速本地迭代：
#   docker build --build-arg BASE_IMAGE=pwnsolver-radare-base ...
ARG BASE_IMAGE=ubuntu:22.04
FROM --platform=linux/amd64 ${BASE_IMAGE}

ENV DEBIAN_FRONTEND=noninteractive \
    LANG=C.UTF-8 \
    LC_ALL=C.UTF-8 \
    PIP_NO_CACHE_DIR=1

RUN if command -v gdb >/dev/null 2>&1 && command -v ruby >/dev/null 2>&1 \
        && command -v gcc >/dev/null 2>&1 && command -v rabin2 >/dev/null 2>&1; then \
        echo "[*] base toolchain already installed"; \
    else \
        apt-get update && apt-get install -y --no-install-recommends \
            bash ca-certificates curl wget git vim less \
            python3 python3-pip python3-dev \
            build-essential gcc g++ gcc-multilib g++-multilib make cmake \
            gdb gdbserver ruby ruby-dev \
            binutils file strace ltrace patchelf pkg-config patch \
            netcat-openbsd socat \
            libc6-dbg libssl-dev libffi-dev zlib1g-dev \
            upx-ucl \
        && rm -rf /var/lib/apt/lists/*; \
    fi

# radare2: jammy apt 未收录，临时使用 noble/universe 二进制包。
# 注意：该步骤会把 libc6 依赖链升级到 noble 的 2.39（与 Ubuntu 24.04 默认一致）。
RUN if command -v rabin2 >/dev/null 2>&1 && command -v r2 >/dev/null 2>&1; then \
        echo "[*] radare2 already installed"; \
    else \
        echo "deb [trusted=yes] http://archive.ubuntu.com/ubuntu noble main universe" \
            > /etc/apt/sources.list.d/noble.list \
        && apt-get update -o Dir::Etc::sourcelist="sources.list.d/noble.list" \
            -o Dir::Etc::sourceparts="-" -o APT::Get::List-Cleanup="0" \
        && apt-get install -y --no-install-recommends radare2 \
        && rm -f /etc/apt/sources.list.d/noble.list \
        && rm -rf /var/lib/apt/lists/*; \
    fi

# Python exploit / analysis toolchain
# 默认走阿里云 PyPI 镜像；如不需要可删除 -i 参数
RUN if python3 -c "import pwn, ropgadget, capstone, unicorn, r2pipe, z3" 2>/dev/null; then \
        echo "[*] python exploit toolchain already installed"; \
    else \
        python3 -m pip install --no-cache-dir -i https://mirrors.aliyun.com/pypi/simple/ \
            pwntools \
            ROPGadget \
            ropper \
            capstone \
            unicorn \
            r2pipe \
            z3-solver \
            LibcSearcher; \
    fi

# Ruby: one_gadget + seccomp-tools（清华 RubyGems 镜像，可在网络受限环境提速）
RUN if command -v one_gadget >/dev/null 2>&1 && command -v seccomp-tools >/dev/null 2>&1; then \
        echo "[*] one_gadget/seccomp-tools already installed"; \
    else \
        gem sources --add https://mirrors.tuna.tsinghua.edu.cn/rubygems/ --remove https://rubygems.org/ \
        && timeout 300 gem install --no-document one_gadget seccomp-tools \
        && one_gadget --version \
        || echo "[warn] one_gadget/seccomp-tools 安装失败，PwnSolver 将自动降级"; \
    fi

# GEF (gdb 增强)；若基础镜像已预置则跳过网络 clone
RUN if [ -f /opt/gef/gef.py ]; then \
        echo "[*] GEF already present in base image"; \
    else \
        git clone --depth 1 https://github.com/bata24/gef /opt/gef; \
    fi \
    && echo "source /opt/gef/gef.py" > /root/.gdbinit

# libc-database 骨架；完整 db 可在需要时执行 /opt/libc-database/get
RUN if [ -f /opt/libc-database/identify ]; then \
        echo "[*] libc-database already present in base image"; \
    else \
        git clone --depth 1 https://github.com/niklasb/libc-database /opt/libc-database; \
    fi \
    && ln -sf /opt/libc-database/identify /usr/local/bin/libc-identify || true

# 常用环境变量与工作目录
ENV PWNSOLVER_X86=1 \
    PYTHONUNBUFFERED=1
WORKDIR /work

COPY . /pwnsolver
RUN python3 -m py_compile /pwnsolver/pwn_solver/reverse_skill.py /pwnsolver/pwn_solver/deep_recon.py || true

VOLUME ["/work"]
CMD ["/bin/bash"]
