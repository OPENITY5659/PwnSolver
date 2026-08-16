#!/usr/bin/env bash
# 从 zhaoxuya520/reverse-skill 同步 PwnSolver 需要的 skill 子集
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
UPSTREAM="${REVERSE_SKILL_UPSTREAM:-https://github.com/zhaoxuya520/reverse-skill.git}"
DEST="$ROOT/reverse_skill"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

echo "[*] cloning upstream (shallow)..."
git clone --depth 1 "$UPSTREAM" "$TMP/reverse-skill"

ITEMS=(
  "skills/pwn-chain"
  "skills/reverse-engineering"
  "skills/radare2"
  "skills/ghidra-reverse"
  "skills/go-rust-reverse"
  "skills/ops/evidence-finding-path.md"
  "skills/ops/scope-contract.md"
  "CTF-Sandbox-Orchestrator/competition-reverse-pwn"
  "LICENSE"
)

for item in "${ITEMS[@]}"; do
  mkdir -p "$DEST/$(dirname "$item")"
  rm -rf "$DEST/$item"
  cp -R "$TMP/reverse-skill/$item" "$DEST/$item"
done

REV="$(git -C "$TMP/reverse-skill" rev-parse HEAD)"
cat > "$DEST/UPSTREAM.md" <<MD
# reverse-skill upstream integration

本目录是从 [zhaoxuya520/reverse-skill](https://github.com/zhaoxuya520/reverse-skill) 抽取的、与 PwnSolver 解题链直接相关的 skill 子集。

- Upstream commit: \`$REV\`
- License: MIT（见本目录 \`LICENSE\`）
- 抽取范围:
  - \`skills/pwn-chain/\`
  - \`skills/reverse-engineering/\`
  - \`skills/radare2/\`
  - \`skills/ghidra-reverse/\`
  - \`skills/go-rust-reverse/\`
  - \`skills/ops/evidence-finding-path.md\` + \`scope-contract.md\`
  - \`CTF-Sandbox-Orchestrator/competition-reverse-pwn/\`

更新方式：

\`\`\`bash
scripts/sync_reverse_skill.sh
\`\`\`
MD
echo "[+] synced at $REV"
