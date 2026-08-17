!/bin/bash
cd "$(dirname "$0")"
echo "[*] PwnSolver GUI (Linux)"
if ! command -v python3 >/dev/null 2>&1; then echo "python3 not found"; exit 1; fi
python3 - <<'PY_INNER'
import sys
sys.path.insert(0, 'pwn_solver')
try:
    from runtime_router import RuntimeRouter
    r = RuntimeRouter()
    print(f"[*] runtime: {r.describe()}")
    if not r.docker_ok:
        print("[-] Docker is required for x86 binaries when running on non-x86 Linux.")
        sys.exit(1)
    if not r.image_ready():
        print("[*] x86 sandbox image not found. Build it in GUI, or run:")
        print("    python3 pwnsolver.py build")
except Exception as exc:
    print(f"[!] router probe failed: {exc}")
PY_INNER
exec python3 pwnsolver.py gui
