#!/bin/bash
# PwnSolver GUI one-click launcher -- Linux
set -euo pipefail
cd "$(dirname "$0")"

if ! command -v python3 >/dev/null 2>&1; then
  echo "[-] python3 not found. Install Python 3.10+ first." >&2
  exit 1
fi

echo "[*] PwnSolver GUI (Linux)"
python3 - <<'PY_INNER'
import os, sys
root = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(root, 'pwn_solver'))
try:
    from runtime_router import RuntimeRouter
    r = RuntimeRouter()
    print(f"[*] runtime: {r.describe()}")
    if r.os_name == 'Linux' and r.machine in ('arm64', 'aarch64') and not r.docker_ok:
        print("[!] Linux ARM64: x86 binaries require Docker. GUI can still do recon.")
    if r.os_name == 'Linux' and r.machine in ('arm64', 'aarch64') and r.docker_ok and not r.image_ready():
        print("[*] x86 sandbox image not found. Use GUI 'Build x86 image' or: python3 pwnsolver.py build")
except Exception as exc:
    print(f"[!] router probe failed (GUI will still start): {exc}")
PY_INNER
exec python3 pwnsolver.py gui
