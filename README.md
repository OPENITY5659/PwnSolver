# PwnSolver

便携式自动 PWN 解题框架，包含两个独立的自动求解器：

- **pwn_solver** — 二进制 PWN 自动解题引擎（ROP / ret2libc / one_gadget / 堆利用 / ORW / 格式字符串等），带 GUI 与 Web 界面
- **phpserialize-solver** — PHP 反序列化漏洞自动解题器（POP 链构造 / payload 生成 / flag 提取）

## 目录结构

```
PwnSolver/
├── pwn_solver/            # 二进制 PWN 解题核心包
│   ├── solver.py          #   主入口：分析 → 判型 → 生成 → 测试 → 爆破 → 自适应决策链
│   ├── analyzer.py        #   静态分析（checksec、危险函数、堆菜单/数组溢出/PRNG/Go 检测）
│   ├── gadget_finder.py   #   ROP 链 / one_gadget / setcontext / xor 等 gadget 收集
│   ├── orw_engine.py      #   ORW 链生成与组合策略
│   ├── heap_exploit.py    #   tcache / unsorted bin / rtld_global 等堆攻击
│   ├── bruteforcer.py     #   偏移 / canary / libc 基址 / one_gadget 爆破
│   ├── adaptive_solver.py #   反馈闭环（失败诊断 → 调参 → 重试）
│   ├── feedback_analyzer.py # 结构化错误诊断（segfault / 退出码解析）
│   ├── multi_stage_leak.py # 多阶段 libc / 堆泄露规划
│   ├── gdb_debugger.py    #   gdb 辅助找偏移 / canary
│   ├── libc_searcher.py   #   基于 LibcSearcher 的 libc 匹配
│   ├── exploit_templates/ #   Ret2Win / Ret2Libc / ROP / Heap / FmtStr 等模板
│   └── ...
├── phpserialize-solver/   # PHP 反序列化解题器
│   ├── solver.py          #   CLI 入口（fetch → analyze → generate → execute）
│   ├── phpuser_gui.py     #   tkinter GUI
│   ├── engine/            #   analyzer / payload / serializer / flag_extractor / http_client
│   └── tests/             #   离线单元测试与 18 关批量测试
├── pwn_gui.py             # PWN 求解器 GUI 入口
├── pwn_web.py             # PWN 求解器 Web 界面入口
├── challenges/            # 练习题目（*.c 源码跟踪；编译出的二进制本地构建，不跟踪）
├── exploits/              # solver 自动生成的时间戳 exploit 脚本（不跟踪，本地产物）
├── pwn题目解析/           # CTF 题目解析资料库（writeup 网页存档、官方 wp、题目附件，含较大二进制）
├── tests/                 # pwn_solver 的 pytest 测试
├── check_env.py           # PWN 环境自检脚本
└── writeup_ctfshow_2025.md
```

## 环境

依赖（可用 `python check_env.py` 自检）：

- pwntools、ROPgadget、capstone、unicorn、LibcSearcher
- 命令行工具：one_gadget、gdb

phpserialize-solver 仅需 `requests`（见 `phpserialize-solver/requirements.txt`）。

## 使用

```bash
# 环境自检
python check_env.py

# PWN GUI
python pwn_gui.py

# PWN Web 界面
python pwn_web.py

# PHP 反序列化 CLI
cd phpserialize-solver
python solver.py -u http://target/        # 目标 URL
python solver.py -a "<?php ... ?>"        # 或直接分析源码

# PHP GUI
python phpuser_gui.py
```

## 测试

```bash
# pwn_solver
pytest tests/

# phpserialize-solver
cd phpserialize-solver
pytest tests/
```

phpserialize-solver 的已知问题与修复进展见 `phpserialize-solver/ISSUES.md`，实测题解见 `phpserialize-solver/WRITEUP.md`。


## 统一智能入口（推荐）

本分支提供唯一入口 `pwnsolver.py`，所有平台自动路由到正确的执行后端：

```bash
python3 pwnsolver.py router                         # 查看当前平台路由决策
python3 pwnsolver.py check                          # 在目标运行时内自检环境
python3 pwnsolver.py build                          # 构建 x86_64 Linux 沙盒镜像

python3 pwnsolver.py solve ./vuln -l ./libc.so.6 -d ./ld-linux-x86-64.so.2 -t 30
python3 pwnsolver.py recon ./vuln --deep-r2         # 仅深度侦察 + playbook
python3 pwnsolver.py gui                            # 启动 GUI
python3 pwnsolver.py web 8787                       # 启动 Web API
python3 pwnsolver.py patterns                       # 查看泛化漏洞模式库
```

Windows 也可使用：`pwnsolver.bat solve .\vuln -l .\libc.so.6`。

## 智能运行时路由

“实际运行题目”统一采用可复现的 Linux x86_64 环境；静态侦察可在宿主机先跑。

| 宿主机 | 二进制架构 | 实际执行后端 |
|---|---|---|
| macOS Apple Silicon (arm64) | x86/x86_64 ELF | **强制** OrbStack/Docker `linux/amd64` 容器 |
| macOS Intel | x86/x86_64 ELF | 优先容器（保证 pwntools/GDB/one_gadget 一致） |
| Linux x86_64 | x86/x86_64 ELF | 本机原生；`PWNSOLVER_FORCE_DOCKER=1` 可强制容器 |
| Linux aarch64 | x86/x86_64 ELF | 强制 `linux/amd64` 容器 |
| Windows | x86/x86_64 ELF | Docker Desktop `linux/amd64` 优先，Docker 不可用回退 WSL2 |
| 任意平台 | arm64 ELF | Linux aarch64 原生；其余建议容器内 qemu/交叉工具链 |

> 结论：**统一容器**是推荐策略。`runtime_router.py` 会自动处理路径映射、目录挂载、
> `SYS_PTRACE`、seccomp 参数与镜像缺失提示。

## 泛化模式库（Pattern Engine）

不再针对单一题目硬编码，而是把题目归纳为可复用模式：

| 模式 ID | 漏洞类型 | 自动策略 | 验证状态 |
|---|---|---|---|
| `ret2win` | 栈溢出 | Ret2WinExploit | ✅ ret2win.c |
| `ret2libc` | 栈溢出 + leak | Ret2LibcExploit | ✅ 基础题目 |
| `format_string` | 格式化字符串 | FormatStringExploit | 基础覆盖 |
| `shellcode` | NX 关闭 | ShellcodeExploit | 基础覆盖 |
| `one_gadget` | 溢出 + libc | OneGadgetExploit | 基础覆盖 |
| `ssal_ret2syscall` | PRNG + stdin-only + syscall 链 | Ret2SyscallExploit | ✅ s.s.a.l |
| `badboy_array_oob` | 有符号索引越界读写 | BadBoyArrayOOBExploit | ✅ BadBoy-2 |
| `yes_or_no` | read-only 抬栈 + one_gadget | YesOrNoExploit | ✅ pwn5_x/pwn |
| `heap_menu` | 堆菜单 UAF/tcache | HeapExploit + rtld_global/setcontext 参数表 | ⚠ 已识别；pwn03/pwn04 全自动待完善 |
| `packed_binary` / `go_binary` | 分诊/符号恢复 | UPX 解包 / Go 符号恢复指引 | 侦察覆盖 |

模式识别在 `pwn_solver/pattern_engine.py`，exploit 生成在 `pwn_solver/exploit_templates/`。
新增同类题目只需补充模式特征，不需要改主决策链。

## reverse-skill 增强（feature/reverse-skill-integration）

- `reverse_skill/` — vendored skill 子集：pwn-chain / reverse-engineering / radare2 / ghidra-reverse / go-rust-reverse / competition-reverse-pwn
- `pwn_solver/deep_recon.py` — rabin2/file/strings 深度分诊，落盘 `pwnsolver_evidence/*.recon.json|md`
- `pwn_solver/reverse_skill.py` — skill 路由、工具探测、`*.playbook.md` 生成
- `solver.py` — 阶段 1.5 DeepRecon、阶段 3.5 playbook、阶段 3 泛化模式 overlay

```bash
# 原 CLI 仍可用
python pwn_solver/solver.py ./vuln --recon-only
python pwn_solver/solver.py ./vuln --no-skill

# 手工容器（统一入口内部会自动调用）
scripts/pwn-x86-build
scripts/pwn-x86 python3 /pwnsolver/pwn_solver/solver.py /ctf/vuln -l /ctf/libc.so.6
```

详细设计见 `docs/REVERSE_SKILL_INTEGRATION.md`。
