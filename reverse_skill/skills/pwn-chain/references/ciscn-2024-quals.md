# CISCN 2024 初赛 PWN 模式（项目内附件已解压验证）

> 附件目录：`pwn题目解析/ciscn/*.7z`。
> WP 来源：CTF-Archives/2024-CISCN-Quals、百度/Google 检索到的公开题解缓存。

## gostack（Day1）
- 类型：Go/CGO 栈溢出；无 canary/PIE，仅 NX。
- 交互：`Input your magic message :`，单次输入。
- WP 要点：
  - 用 `\x00` 填充绕过 bufio Scanner 提前停止条件。
  - 偏移：rbp - 缓冲区 = 0x1c8。
  - 二段 ROP：`read(0,bss,8)` 写 `/bin/sh`，再 `execve("/bin/sh",0,0)`。
  - 关键 gadget：`syscall=0x404043, pop_rax=0x40f984, pop_rsi=0x42138a, pop_rdx=0x4944ec, pop_rdi=0x4a18a5`。
- PwnSolver 优化：快速 Go 识别，跳过 objdump/ROPgadget 全量扫描。

## orange_cat_diary（Day1）
- 类型：glibc 2.23 堆菜单；保护全开；经典 House of Orange + fastbin attack。
- 特征：`1.Add diary / 2.Show / 3.Delete / 4.Edit / 5.Exit`；
  delete/show 只能用一次；chunk_ptr 始终指向最新 chunk；存在 UAF 与 edit 8 字节溢出。
- PwnSolver 优化：字符串菜单识别，stripped 非 scanf 菜单也能判 heap_menu。

## ezbuf（Day1）
- 类型：protobuf-c 协议解析 + 堆漏洞；libseccomp 过滤。
- 特征：`new.pb-c.c`、`heybro__pack/unpack`、`message->base.descriptor`、
  ProtobufCMessageDescriptor magic `0x28AAEEF9`。
- WP 提示：先恢复 protobuf 结构，再审计 unpack 时的 size/index 混淆。
- PwnSolver 优化：DeepRecon 识别 protobuf-c 与 seccomp。

## EzHeap（Day2）
- 类型：堆溢出 + seccomp；PIE/canary/Full RELRO。
- 特征：`1. malloc heap / 2. free heap / 3. edit heap / 4. show heap / 5. exit`。
- WP 提示：借助残留 heap 泄露 libc/heap，绕过 safe-linking，House of Apple 2。

## 泛化结论
- 菜单题：不应只看 free/calloc/scanf 计数，字符串菜单也要判 heap。
- Go/CGO：先识别 runtime，禁止进入 ROPgadget 全量路径。
- seccomp：一律禁止 one_gadget/ret2libc 首选，必须 ORW 或功能复用。
- protobuf：先恢复 message descriptor，再找 unpack 边界，而不是找栈溢出。
