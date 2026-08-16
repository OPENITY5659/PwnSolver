# PwnSolver Reverse-Skill 集成

PwnSolver 在原有 `analyzer → gadget → exploit → test` 决策链之外，引入了 reverse-skill 的三项增强：

1. **Skill Router（技能路由）**：根据二进制类型、保护机制、语言运行时和漏洞类型，从 reverse-skill 知识库中自动选出 `pwn-chain`、`reverse-engineering`、`radare2`、`ghidra-reverse`、`go-rust-reverse` 等 skill，并生成本次解题的 RE/PWN playbook。
2. **Deep Recon（深度侦察）**：基于 `rabin2`/`objdump`/`strings` 的结构化分诊，输出 packer、Go/Rust 运行时、反分析、导入导出、hash/熵等证据，并落成 JSON/Markdown evidence。
3. **x86_64 Linux 沙盒（OrbStack/Docker）**：Apple Silicon 宿主机执行 `scripts/pwn-x86`，自动构建并进入 amd64 解题容器，保证 x86 CTF 题目的 pwntools/GDB/one_gadget 链路可用。

CLI:

```bash
python3 pwn_solver/solver.py ./vuln --recon-only          # 仅执行 reverse-skill 增强侦察
python3 pwn_solver/solver.py ./vuln --no-skill            # 关闭 skill 增强
python3 pwn_solver/solver.py ./vuln --skill-root ./reverse_skill
```

Sandbox:

```bash
scripts/pwn-x86                          # 进入 x86_64 Ubuntu 解题容器
scripts/pwn-x86 python3 solver.py ./vuln # 容器内跑 PwnSolver
scripts/pwn-x86-build                    # 仅构建镜像
```
