# CISCN PWN benchmark

- root: /private/tmp/ciscnbench
- mode: solve

## gostack
- rc=0 elapsed=5.44s
- vuln: go_stack@92
- patterns: go_stack_overflow(92) -> go_binary(70)
- success: True

## orange_cat_diary
- rc=0 elapsed=5.91s
- vuln: orange_cat@99
- patterns: orange_cat_diary(99) -> heap_menu(97) -> one_gadget(90) -> ret2libc(88) -> format_string(78)
- success: True

## pwn
- rc=1 elapsed=5.63s
- vuln: one_gadget@90
- patterns: one_gadget(90) -> ret2libc(88) -> format_string(78) -> protobuf_protocol(75)
- success: False

## EzHeap
- rc=1 elapsed=5.2s
- vuln: heap@97
- patterns: heap_menu(97) -> one_gadget(90) -> ret2libc(88) -> format_string(78)
- success: False
