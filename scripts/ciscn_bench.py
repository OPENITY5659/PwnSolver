#!/usr/bin/env python3
"""CISCN PWN batch benchmark: run PwnSolver against every extracted ELF and collect errors.

Usage:
  python3 scripts/ciscn_bench.py --root /path/to/extracted --mode recon|solve
"""
import argparse
import json
import os
import re
import subprocess
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
ENTRY = ROOT / 'pwnsolver.py'


def find_elf_binaries(root: Path):
    out = []
    for path in sorted(root.rglob('*')):
        if not path.is_file():
            continue
        low = path.name.lower()
        if low.endswith('.so') or low.startswith('lib') or low.startswith('ld-'):
            continue
        try:
            with open(path, 'rb') as f:
                magic = f.read(4)
            if magic == b'\x7fELF':
                out.append(path)
        except Exception:
            pass
    return out


def detect_aux(binary: Path):
    d = binary.parent
    libc = ld = None
    for base in (d, d.parent):
        if not base.exists():
            continue
        try:
            names = os.listdir(base)
        except Exception:
            continue
        for n in names:
            low = n.lower()
            p = base / n
            if low.startswith('libc') and low.endswith(('.so', '.so.6', '.so.6-2.23')) and p.is_file():
                libc = str(p)
            elif 'ld-linux' in low and p.is_file():
                ld = str(p)
    # 2.23 附件通常不随包分发 loader；使用仓库内 glibc-compat loader。
    if libc and not ld and '2.23' in Path(libc).name:
        compat = ROOT / 'pwn_solver' / 'glibc_compat' / 'ld-2.23.so'
        if compat.exists():
            ld = str(compat)
    return libc, ld


def run_one(binary: Path, mode: str, timeout: int):
    libc, ld = detect_aux(binary)
    cmd = [sys.executable, str(ENTRY), 'recon' if mode == 'recon' else 'solve', str(binary)]
    if libc:
        cmd += ['-l', libc]
    if ld:
        cmd += ['-d', ld]
    cmd += ['-t', '25']
    started = time.time()
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, errors='replace', timeout=timeout, stdin=subprocess.DEVNULL)
        rc = proc.returncode
        text = (proc.stdout or '') + '\n' + (proc.stderr or '')
    except subprocess.TimeoutExpired:
        rc = -999
        text = '[benchmark timeout]'
    elapsed = time.time() - started
    vuln = 'unknown'
    m = re.search(r'选择策略:\s*(\S+)\s*\(置信度:\s*(\d+)\)', text)
    if m:
        vuln = f'{m.group(1)}@{m.group(2)}'
    patterns = []
    m = re.search(r'泛化模式:\s*(.+)', text)
    if m:
        patterns = [x.strip() for x in m.group(1).split('->')]
    success = rc == 0 and ('解题成功' in text or '★ ✅ 解题成功' in text)
    errors = []
    for line in text.splitlines():
        if any(k in line for k in ('[!] 错误', 'Traceback', 'NameError', 'IndentationError', 'AttributeError', '测试失败', '超时')):
            errors.append(line.strip()[:240])
    return {
        'binary': str(binary),
        'relative': str(binary.relative_to(ROOT.parent)) if str(binary).startswith(str(ROOT)) else binary.name,
        'mode': mode,
        'rc': rc,
        'elapsed': round(elapsed, 2),
        'vuln': vuln,
        'patterns': patterns,
        'success': success,
        'errors': errors[:8],
        'evidence_dir': str(binary.parent / 'pwnsolver_evidence'),
    }


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--root', required=True)
    ap.add_argument('--mode', choices=['recon', 'solve'], default='recon')
    ap.add_argument('--timeout', type=int, default=110)
    ap.add_argument('--tag', default='last', help='report file suffix')
    args = ap.parse_args()
    root = Path(args.root).resolve()
    bins = find_elf_binaries(root)
    print(f'[*] found {len(bins)} ELF binaries under {root}')
    results = []
    for i, binary in enumerate(bins, 1):
        print(f'[{i}/{len(bins)}] {binary.name} ({args.mode})', flush=True)
        r = run_one(binary, args.mode, args.timeout)
        results.append(r)
        print(f"    rc={r['rc']} vuln={r['vuln']} patterns={','.join(r['patterns'])} errors={len(r['errors'])} success={r['success']}")
    report = {
        'generated_at': time.strftime('%Y-%m-%d %H:%M:%S'),
        'root': str(root),
        'mode': args.mode,
        'results': results,
    }
    out_dir = ROOT / 'reports'
    out_dir.mkdir(exist_ok=True)
    out_json = out_dir / f'ciscn_bench_{args.tag}.json'
    out_md = out_dir / f'ciscn_bench_{args.tag}.md'
    out_json.write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding='utf-8')
    lines = ['# CISCN PWN benchmark', '', f'- root: {root}', f'- mode: {args.mode}', '']
    for r in results:
        lines.append(f"## {Path(r['binary']).name}")
        lines.append(f"- rc={r['rc']} elapsed={r['elapsed']}s")
        lines.append(f"- vuln: {r['vuln']}")
        lines.append(f"- patterns: {' -> '.join(r['patterns'])}")
        lines.append(f"- success: {r['success']}")
        if r['errors']:
            lines.append('- errors:')
            for e in r['errors']:
                lines.append(f'  - `{e}`')
        lines.append('')
    out_md.write_text('\n'.join(lines), encoding='utf-8')
    print(f'[*] report: {out_json}')
    print(f'[*] report: {out_md}')
    failed = [r for r in results if not r['success']]
    if args.mode == 'solve':
        print(f'[*] summary: {len(results) - len(failed)}/{len(results)} solved, {len(failed)} failed')
        return 1 if failed else 0
    print(f'[*] summary: recon completed for {len(results)} binaries ({len(failed)} marked unsolved as expected)')
    return 0


if __name__ == '__main__':
    sys.exit(main())
