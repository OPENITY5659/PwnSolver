#!/usr/bin/env python3
"""PwnSolver unified entrypoint with smart runtime routing.

Examples:
  python3 pwnsolver.py router
  python3 pwnsolver.py solve ./vuln -l ./libc.so.6 -d ./ld-linux-x86-64.so.2 -t 30
  python3 pwnsolver.py recon ./vuln --deep-r2
  python3 pwnsolver.py gui
  python3 pwnsolver.py web [port]
  python3 pwnsolver.py check
  python3 pwnsolver.py patterns
"""
import argparse
import os
import shlex
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT / 'pwn_solver'))

from runtime_router import RuntimeRouter, X86_IMAGE, PROJECT_ROOT, SOLVER_SCRIPT


def _find_option(args, names):
    for i, a in enumerate(args):
        if a in names and i + 1 < len(args):
            return args[i + 1]
        if a.startswith('--libc='):
            return a.split('=', 1)[1]
        if a.startswith('--ld='):
            return a.split('=', 1)[1]
    return None


def _mapped_args(args, plan, libc, ld):
    out = []
    skip = False
    for i, a in enumerate(args):
        if skip:
            skip = False
            continue
        if a in ('-l', '--libc', '-d', '--ld'):
            out.append(a)
            val = args[i + 1] if i + 1 < len(args) else ''
            if val:
                out.append(plan.map_path(val))
            skip = True
            continue
        if a.startswith('--libc='):
            out.append('--libc=' + plan.map_path(a.split('=', 1)[1]))
            continue
        if a.startswith('--ld='):
            out.append('--ld=' + plan.map_path(a.split('=', 1)[1]))
            continue
        out.append(a)
    return out


def _run(plan, args, interactive=False, image_ready=True):
    cmd = plan.build_command(args, interactive=interactive)
    print(f'[*] runtime: {plan.describe()}')
    if plan.backend == 'docker-amd64' and not image_ready:
        print(f'[-] image {X86_IMAGE} not found. Build it first:', file=sys.stderr)
        print(f'    scripts/pwn-x86-build   (or: python3 pwnsolver.py build)', file=sys.stderr)
        return 2
    if plan.backend == 'docker-amd64':
        print('[*] docker command: ' + ' '.join(shlex.quote(x) for x in cmd), file=sys.stderr)
    return subprocess.call(cmd)


def cmd_router(_args):
    r = RuntimeRouter()
    status = r.status()
    print('PwnSolver runtime router')
    print('=======================')
    for k, v in status.items():
        print(f'  {k:14s}: {v}')
    print(f'  rule        : {r.describe()}')
    return 0 if r.docker_ok or r.wsl_ok or r.os_name == 'Linux' else 1


def cmd_build(_args):
    script = PROJECT_ROOT / 'scripts' / 'pwn-x86-build'
    return subprocess.call([str(script)])


def cmd_solve(args, recon_only=False):
    binary = args.binary
    libc = args.libc or _find_option(args.solver_args, ('-l', '--libc'))
    ld = args.ld or _find_option(args.solver_args, ('-d', '--ld'))
    # 7z/zip 解包通常会丢失 executable bit，宿主机先补齐，避免容器内 process() 报错。
    for path in (binary, libc, ld):
        if path and os.path.exists(path):
            try:
                os.chmod(path, os.stat(path).st_mode | 0o111)
            except Exception:
                pass
    r = RuntimeRouter()
    plan = r.plan(binary, libc, ld)
    if plan.backend == 'error':
        print(f'[-] no usable runtime: {plan.reason}', file=sys.stderr)
        return 1
    extra = list(args.solver_args)
    if recon_only and '--recon-only' not in extra:
        extra.append('--recon-only')
    if args.no_skill and '--no-skill' not in extra:
        extra.append('--no-skill')
    mapped = _mapped_args(extra, plan, libc, ld)
    mapped_binary = plan.map_path(binary)
    if plan.backend == 'docker-amd64':
        solver = '/pwnsolver/pwn_solver/solver.py'
    else:
        solver = plan.map_path(str(SOLVER_SCRIPT))
    inner = 'python3 -W ignore ' + shlex.quote(solver) + ' ' + shlex.quote(mapped_binary)
    if mapped:
        inner += ' ' + ' '.join(shlex.quote(x) for x in mapped)
    return _run(plan, inner, image_ready=r.image_ready())


def cmd_check(_args):
    r = RuntimeRouter()
    if r.os_name == 'Darwin' and r.machine in ('arm64', 'aarch64'):
        plan = r._docker_plan(str(PROJECT_ROOT / 'README.md'), '', '', reason='environment check')
        if not r.image_ready():
            print(f'[-] image {X86_IMAGE} not ready; run scripts/pwn-x86-build', file=sys.stderr)
            return 2
        return _run(plan, 'cd /pwnsolver && python3 check_env.py', image_ready=r.image_ready())
    if r.os_name == 'Windows' and r.docker_ok:
        plan = r._docker_plan(str(PROJECT_ROOT / 'README.md'), '', '', reason='environment check')
        return _run(plan, 'cd /pwnsolver && python3 check_env.py', image_ready=r.image_ready())
    return subprocess.call([sys.executable, str(PROJECT_ROOT / 'check_env.py')])


def cmd_patterns(_args):
    from pattern_engine import PatternEngine
    print('Generalized exploitation patterns:')
    for pid, name in sorted(PatternEngine.VULN_MAP.items()):
        print(f'  {pid:20s} -> vuln_type={name}')
    return 0


def main():
    parser = argparse.ArgumentParser(description='PwnSolver unified entrypoint')
    sub = parser.add_subparsers(dest='command')

    p_solve = sub.add_parser('solve', help='solve a binary through smart runtime router')
    p_solve.add_argument('binary')
    p_solve.add_argument('solver_args', nargs=argparse.REMAINDER)
    p_solve.add_argument('-l', '--libc')
    p_solve.add_argument('-d', '--ld')
    p_solve.add_argument('--no-skill', action='store_true')

    p_recon = sub.add_parser('recon', help='recon-only through smart runtime router')
    p_recon.add_argument('binary')
    p_recon.add_argument('solver_args', nargs=argparse.REMAINDER)
    p_recon.add_argument('-l', '--libc')
    p_recon.add_argument('-d', '--ld')
    p_recon.add_argument('--no-skill', action='store_true')

    sub.add_parser('gui', help='launch PwnSolver GUI')
    p_web = sub.add_parser('web', help='launch PwnSolver web API')
    p_web.add_argument('port', nargs='?', default='8787')
    sub.add_parser('check', help='check environment in selected runtime')
    sub.add_parser('router', help='show runtime routing decision')
    sub.add_parser('build', help='build x86_64 Linux sandbox image')
    sub.add_parser('patterns', help='list generalized exploitation patterns')

    args = parser.parse_args()
    if args.command in (None, 'gui'):
        script = ROOT / 'pwn_gui.py'
        return subprocess.call([sys.executable, str(script)])
    if args.command == 'web':
        return subprocess.call([sys.executable, str(ROOT / 'pwn_web.py'), args.port])
    if args.command == 'check':
        return cmd_check(args)
    if args.command == 'router':
        return cmd_router(args)
    if args.command == 'build':
        return cmd_build(args)
    if args.command == 'patterns':
        return cmd_patterns(args)
    if args.command == 'solve':
        return cmd_solve(args)
    if args.command == 'recon':
        return cmd_solve(args, recon_only=True)
    parser.print_help()
    return 1


if __name__ == '__main__':
    sys.exit(main())
