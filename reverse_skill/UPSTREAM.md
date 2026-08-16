# reverse-skill upstream integration

本目录是从 [zhaoxuya520/reverse-skill](https://github.com/zhaoxuya520/reverse-skill) 抽取的、与 PwnSolver 解题链直接相关的 skill 子集。

- Upstream commit: `ea582f30d53e4d616881df06a8e0f7e9f661ea21`
- License: MIT（见本目录 `LICENSE`）
- 抽取范围:
  - `skills/pwn-chain/`
  - `skills/reverse-engineering/`
  - `skills/radare2/`
  - `skills/ghidra-reverse/`
  - `skills/go-rust-reverse/`
  - `skills/ops/evidence-finding-path.md` + `scope-contract.md`
  - `CTF-Sandbox-Orchestrator/competition-reverse-pwn/`

更新方式：

```bash
scripts/sync_reverse_skill.sh
```
