# CTFshow 2024 元旦水友赛 PWN 官方 WP 模式

> 来源：仓库内 `pwn题目解析/元旦水友赛/CTFshow元旦水友赛官方wp.docx`。
> 本文件是 PwnSolver 的验证/回归基线。

## pwn1 BadBoy（PwnSolver 已覆盖）
- libc 2.27；Partial RELRO + canary + NX + no PIE。
- 漏洞：`scanf("%ld")` 写入栈上 byte 索引，`write(fd, buf+idx, len)` 越界读；第二次 `scanf("%lld")`
  负数索引绕过 `<=8` 检查，`read(0, buf+idx, 3)` 三字节任意写。
- 利用：idx=40 泄露 stack，idx=24 泄露 `__libc_start_call_main` 低 3 字节；
  `puts@got` 三字节覆写为 `system`，`buf="sh\0"`。
- 关键公式：`system = leak_low3 - 0x21c87 + libc.sym['system']`。
- stack-delta 因 argv 布局可能变化：官方 0xf8，自定义 loader 本地常为 0xf0；
  PwnSolver 的 `BadBoyArrayOOBExploit` 会依次尝试 `0xf8/0xf0/...`。

## pwn2 s.s.a.l（PwnSolver 已覆盖）
- libc 2.27；无输出函数、无 canary、no PIE。
- 利用：seed=370424 让伪随机重排出 `/bin/sh` 到 `d`；
  `zz955` 置 rax=59；`pop rsi; pop rdi; ret`；`sar rdx,0x14; xor rdx,[rsp+8]` 清零 rdx；
  首轮栈上预置 `0x50`；最后 `syscall`。
- 陷阱：不能把 payload ljust 到 0x58，否则覆盖 `[rsp+8]=0x50`；
  多阶段 read/scanf 之间需要 settle sleep。

## pwn3 Happy_New_Year（PwnSolver 待实现自动利用）
- libc 2.27；heap 菜单 `Add/Show/Edit/Delete/Quit`。
- WP 路径：unsorted-bin leak libc + heap；tcache poison 到 `_rtld_global-0x20`；
  fake link_map 的 fini 指向 one_gadget；退出触发。
- 关键偏移（libc 2.27）：unsorted 0x3ec090，rtld_global 0x61b060，
  l_name 0x61c710，one_gadget 0x4f302。

## pwn4 Heap_Harmony_Festivity（PwnSolver 待实现自动利用）
- libc 2.31；同款 heap 菜单。
- WP 路径：unsorted-bin leak；tcache poison `_rtld_global-0x20`；
  fake link_map + setcontext 链；退出后 ORW 读 flag。
- 关键偏移（libc 2.31-0ubuntu9.16）：unsorted 0x1ebfd0，rtld_global 0x222060，
  setcontext gadget 0x580dd，ret 0x25679，pop_rdi 0x26b72，pop_rsi 0x27529，
  pop_rdx_r12 0x11c1e1。

## pwn5 yes_or_no（PwnSolver 待完善自动爆破）
- 栈可重复进入 `yes()`，用 `pop r12/r15` 清空 one_gadget 约束，抬栈后爆破 one_gadget 低 3 字节。
- 官方：`one=0xe3b2e`，`pop_r12=0x401176`，`pop_r15=0x401179`，`yes=0x401150`。
