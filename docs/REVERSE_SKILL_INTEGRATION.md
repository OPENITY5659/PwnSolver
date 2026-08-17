# PwnSolver × reverse-skill 加强设计文档

分支：`feature/reverse-skill-integration`

## 1. 目标

PwnSolver 原有的 `analyze -> gadget -> exploit -> test` 决策链主要解决“已经拿到干净 ELF
且漏洞模型比较简单”的情况。结合 [zhaoxuya520/reverse-skill](https://github.com/zhaoxuya520/reverse-skill)
后，补齐以下能力：

1. **先逆向、后利用**：stripped / packed / Go / Rust / 反调试样本先做分诊与符号恢复，
   再进入 ROP / heap / fmtstr 流程。
2. **证据链**：按 `Evidence -> Finding -> Path` 落盘 hash、file type、rabin2 结构、
   字符串、导入表、保护机制、工具状态，便于复现与写 writeup。
3. **技能路由**：自动选择 `pwn-chain`、`reverse-engineering`、`radare2`、
   `ghidra-reverse`、`go-rust-reverse`、`competition-reverse-pwn`。
4. **x86_64 Linux 沙盒**：Apple Silicon (M4) 宿主机通过 OrbStack 运行 amd64 容器，
   避免 arm64 环境无法执行 x86 CTF 题的问题。

## 2. 目录结构

```text
reverse_skill/
  skills/pwn-chain/                       # 从漏洞点到 working exploit
  skills/reverse-engineering/             # ELF/Go/Rust/反分析/CTF 模式库
  skills/radare2/                         # CLI 侦察
  skills/ghidra-reverse/                  # 开源反编译
  skills/go-rust-reverse/                 # Go/Rust stripped 恢复
  skills/ops/                             # Evidence/scope 契约
  CTF-Sandbox-Orchestrator/competition-reverse-pwn/
  UPSTREAM.md                             # 上游 commit 与同步方法

pwn_solver/reverse_skill.py               # skill 加载/路由/工具探测/playbook
pwn_solver/deep_recon.py                  # rabin2 + file + strings 深度侦察
pwn_solver/solver.py                      # 阶段 1.5 与 playbook 阶段
tests/test_reverse_skill.py               # 无 pwntools 依赖的集成测试

docker/pwn-x86.Dockerfile                 # amd64 Ubuntu PWN 环境（22.04 + radare2 2.39 依赖链）
scripts/pwn-x86                           # 进入/在容器内执行命令
scripts/pwn-x86-build                     # 构建镜像
scripts/sync_reverse_skill.sh             # 更新 vendored skills
```

## 3. 运行流程变化

```text
stage 1    PwnSolver 原有基础分析（pwntools ELF/checksec/objdump）
stage 1.5  DeepRecon:
             sha256/md5/sha1 + file + entropy + magic
             rabin2 -I -S -i -E -z
             packer / Go / Rust / C++ / anti-debug / seccomp 检测
             Evidence JSON/Markdown -> pwnsolver_evidence/
stage 2    gadget 收集（原逻辑）
stage 3    漏洞类型判断（原逻辑 + reverse_intel 组合信号）
stage 3.5  reverse-skill playbook:
             路由结果、执行清单、关键参考、常见坑、工具缺失表
             -> pwnsolver_evidence/<name>.playbook.md
stage 4+   exploit 生成/测试/自适应（原逻辑，远程稳定化清单已注入）
```

DeepRecon 和 reverse_skill 模块**不依赖 pwntools**，因此工具链不完整时也能先拿到
侦察报告，再进入容器补齐依赖。

## 4. CLI

```bash
# 原命令全部兼容
python3 pwn_solver/solver.py ./vuln -l ./libc.so.6

# 仅侦察：不生成/测试 exploit
python3 pwn_solver/solver.py ./vuln --recon-only

# 额外 r2 aaa 函数级分析
python3 pwn_solver/solver.py ./vuln --recon-only --deep-r2

# 关闭 reverse-skill 增强，回退到原行为
python3 pwn_solver/solver.py ./vuln --no-skill

# 指定 skill 根目录
python3 pwn_solver/solver.py ./vuln --skill-root /path/to/reverse-skill
```

### x86_64 容器

```bash
scripts/pwn-x86-build
scripts/pwn-x86
scripts/pwn-x86 python3 /pwnsolver/pwn_solver/solver.py /ctf/vuln --recon-only
scripts/pwn-x86 bash -lc "cd /ctf && python3 /pwnsolver/pwn_solver/solver.py ./vuln -l ./libc.so.6"
```

挂载规则：

- 仓库根目录 -> `/pwnsolver`
- 当前目录在仓库外时 -> `/ctf`
- 当前目录在仓库内时 -> `/pwnsolver/<relative-path>`

容器包含 pwntools / ROPGadget / Ropper / capstone / unicorn / z3-solver /
gdb + GEF / one_gadget / seccomp-tools / radare2 / patchelf / libc-database 骨架。

## 5. Skill 路由规则

| 信号 | 命中 skill | 作用 |
|---|---|---|
| PwnSolver 任务 | `pwn-chain` | working exploit 流程 |
| vuln_type=ret2* / one_gadget | `pwn-chain/references/stack-pwn.md` | ret2libc / 栈对齐 / ret2csu |
| vuln_type=heap | `pwn-chain/references/heap-pwn.md` | glibc 版本矩阵 / tcache / FILE |
| stripped | `reverse-engineering` + `ghidra-reverse` | 符号恢复 / headless 反编译 |
| packed | `reverse-engineering` | 脱壳 / OEP dump |
| Go/Rust markers | `go-rust-reverse` | pclntab / panic string 分析 |
| rabin2/r2 可用 | `radare2` | 导入表证据（硬门禁） |
| Evidence 模式 | `competition-reverse-pwn` | artifact 保留 / crash 证据 |

## 6. 已注入的 pwn-chain 工程约束

- 远程交互优先 `sendlineafter` / `recvuntil` 锚字符串，禁止模糊 sleep。
- x86_64 `system()` 前补 `ret` gadget 保证 rsp 16 字节对齐。
- libc 必须用 leaked 地址反查 `libc-database` 验证版本，不拍脑袋假设 Ubuntu 版本。
- 堆题先确认 glibc 版本：2.27 tcache / 2.32 safe-linking / 2.34 移除 hook。
- 远程成功后连续运行 20 次以上验证稳定性。

## 7. 测试

```bash
# 无 pwntools 依赖的 reverse-skill 集成测试
python3 tests/test_reverse_skill.py

# 容器内完整测试
scripts/pwn-x86 bash -lc "cd /pwnsolver && pytest -q tests/test_reverse_skill.py"
```

## 8. 上游同步

```bash
scripts/sync_reverse_skill.sh
```

该脚本只复制 PwnSolver 实际消费的 skill 子集，不会把整个 reverse-skill 仓库
（含 burp-mcp、40+ CTF 子技能等无关内容）带入本仓库。


## 9. 实测验证记录（容器内 x86_64）

| 题目 | 来源 | 结果 |
|---|---|---|
| ret2win.c | 仓库 challenges | ✅ 全自动成功 |
| s.s.a.l | CTFshow 2024 元旦 pwn2 | ✅ 自动 ret2syscall 成功 |
| BadBoy-2 | CTFshow 2024 元旦 pwn1 | ✅ 自动 BadBoy array-OOB 成功 |
| pwn03 Happy_New_Year | CTFshow 2024 元旦 pwn3 | ⚠ 已识别 heap 菜单；自动利用待实现（官方 WP 偏移已收录） |
| pwn04 Heap_Harmony_Festivity | CTFshow 2024 元旦 pwn4 | ⚠ 已识别 heap 菜单；setcontext+ORW 自动利用待实现 |
| pwn5 yes_or_no | CTFshow 2024 元旦 pwn5 | ✅ 自动 yes_or_no 抬栈 + one_gadget 成功（需 libc-2.31.so） |

关键修复：
- `find_pop_rsi_rdi_gadget` 之前会选中带 `add bl, al` 前缀的伪 gadget。
- `Ret2SyscallExploit` 之前 PRNG 循环体缩进错误、`p.clean` 破坏 stdin-only 题目、payload padding 覆盖 `0x50`。
- `BaseExploit.launch_code` 改用 loader `--library-path`，避免目标 shell 继承旧 libc 路径。
- 新增 BadBoy 签名检测与 `BadBoyArrayOOBExploit`、`YesOrNoExploit`。
- GUI 增加 reverse-skill/recon/x86 sandbox 开关、LD 自动检测、报告入口、环境自检。


## 10. 智能运行时路由与统一入口

新增 `pwn_solver/runtime_router.py` 与根目录 `pwnsolver.py`：

```bash
python3 pwnsolver.py router
python3 pwnsolver.py check
python3 pwnsolver.py solve ./vuln -l ./libc.so.6 -d ./ld-linux-x86-64.so.2
python3 pwnsolver.py recon ./vuln --deep-r2
python3 pwnsolver.py gui
python3 pwnsolver.py web
python3 pwnsolver.py patterns
```

路由规则：

- macOS Apple Silicon：强制 `linux/amd64` Docker/OrbStack 容器。
- Linux x86_64：默认本机；`PWNSOLVER_FORCE_DOCKER=1` 可统一容器。
- Linux aarch64：x86 ELF 强制容器。
- Windows：Docker Desktop 优先，不可用时回退 WSL2。
- 自动处理 binary/libc/ld 目录挂载、`SYS_PTRACE`、seccomp 参数、镜像缺失提示。

## 11. 泛化模式引擎

新增 `pwn_solver/pattern_engine.py`，把题目归类到可复用模式而不是单一文件特判：

`ret2win` / `ret2libc` / `format_string` / `shellcode` / `one_gadget` /
`ssal_ret2syscall` / `badboy_array_oob` / `yes_or_no` / `heap_menu` /
`packed_binary` / `go_binary`。

`solver.py` 在阶段 3 会把 PatternEngine 的结果 overlay 到原有判型结果；
playbook 也会输出 “泛化模式” 章节。
