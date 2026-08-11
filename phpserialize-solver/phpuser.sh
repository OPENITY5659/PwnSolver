#!/usr/bin/env bash
set -e
cd "$(dirname "$0")"

echo "============================================"
echo "  PHPUnser GUI — Portable Launcher"
echo "============================================"
echo

# Check Python
if ! command -v python3 &>/dev/null; then
    echo "[ERROR] Python 3 is not installed."
    exit 1
fi

# Create venv if missing
if [ ! -f ".venv/bin/python" ]; then
    echo "[*] Creating virtual environment..."
    python3 -m venv .venv
    echo "[*] Installing dependencies..."
    .venv/bin/pip install requests
    echo "[*] Setup complete."
fi

echo "[*] Starting PHPUnser GUI..."
.venv/bin/python phpuser_gui.py
