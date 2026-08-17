# CISCN PWN benchmark

- root: /private/tmp/ciscnbench2025
- mode: solve

## proxy
- rc=1 elapsed=20.92s
- vuln: one_gadget@95
- patterns: packed_binary(99) -> one_gadget(90) -> ret2libc(88) -> format_string(78)
- success: False
- errors:
  - `[-] 本地测试失败: segfault @ 0x7fffff691b01 (exit=0)`
  - `[-] 本地测试失败: wrong_output (exit=0)`
  - `[-] 本地测试失败: segfault @ 0x7fffff691b01 (exit=0)`

## server
- rc=1 elapsed=17.25s
- vuln: one_gadget@95
- patterns: one_gadget(90) -> ret2libc(88) -> format_string(78)
- success: False
- errors:
  - `[-] 本地测试失败: eof (exit=1)`
  - `stderr: Traceback (most recent call last):`
  - `[feedback] ✗ 超时`
  - `[-] 本地测试失败: timeout (exit=0)`
  - `[-] 本地测试失败: eof (exit=1)`
  - `stderr: Traceback (most recent call last):`
  - `[-] 本地测试失败: eof (exit=1)`
  - `stderr: Traceback (most recent call last):`

## main
- rc=1 elapsed=28.99s
- vuln: one_gadget@90
- patterns: one_gadget(90) -> ret2libc(88) -> format_string(78)
- success: False
- errors:
  - `[feedback] ✗ 超时`
  - `[-] 本地测试失败: timeout (exit=0)`
  - `[-] 本地测试失败: unknown (exit=0)`
  - `[-] 本地测试失败: unknown (exit=0)`
  - `[-] 本地测试失败: segfault @ 0x7fffff66ab01 (exit=0)`

## pwn
- rc=1 elapsed=33.38s
- vuln: ret2win@96
- patterns: ret2win(96) -> one_gadget(90) -> ret2libc(88) -> format_string(78)
- success: False
- errors:
  - `[-] 本地测试失败: wrong_output (exit=0)`
  - `[-] 本地测试失败: segfault @ 0x7fffff3c536a (exit=0)`
  - `[feedback] ✗ 超时`
  - `[-] 本地测试失败: timeout (exit=0)`
  - `[-] 本地测试失败: wrong_output (exit=0)`
