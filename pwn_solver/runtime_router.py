#!/usr/bin/env python3
"""PwnSolver cross-platform execution backend router.

Unified runtime policy:
- macOS Apple Silicon (arm64) -> mandatory Docker/OrbStack linux/amd64 container
- Linux x86_64 -> native (or force Docker with PWNSOLVER_FORCE_DOCKER=1)
- Linux aarch64 -> x86 ELF goes to linux/amd64 container
- Windows -> Docker Desktop linux/amd64 first, WSL2 fallback
"""
from __future__ import annotations

import os
import platform
import shlex
import shutil
import subprocess
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Sequence, Tuple

PROJECT_ROOT = Path(__file__).resolve().parent.parent
SOLVER_SCRIPT = PROJECT_ROOT / 'pwn_solver' / 'solver.py'
DOCKERFILE = PROJECT_ROOT / 'docker' / 'pwn-x86.Dockerfile'
X86_IMAGE = os.environ.get('PWNSOLVER_X86_IMAGE', 'pwnsolver-x86:latest')


@dataclass
class RuntimePlan:
    backend: str
    host_os: str
    host_arch: str
    image: str = X86_IMAGE
    mounts: List[Tuple[str, str]] = field(default_factory=list)
    workdir: str = '/ctf0'
    reason: str = ''
    mandatory: bool = False

    def describe(self) -> str:
        return f'{self.backend} ({self.host_os}/{self.host_arch}) — {self.reason}'

    def build_command(self, inner: str, interactive: bool = False) -> List[str]:
        if self.backend == 'docker-amd64':
            cmd = ['docker', 'run', '--platform', 'linux/amd64', '--rm']
            cmd.append('-it' if interactive else '-i')
            cmd += ['--cap-add=SYS_PTRACE', '--security-opt', 'seccomp=unconfined']
            for host, container in self.mounts:
                cmd += ['-v', f'{host}:{container}']
            cmd += [
                '-w', self.workdir,
                '-e', 'PWNSOLVER_X86=1',
                '-e', 'PYTHONUNBUFFERED=1',
                self.image,
            ]
            if interactive:
                cmd += ['/bin/bash']
            else:
                cmd += ['bash', '-lc', inner]
            return cmd
        if self.backend == 'wsl':
            return ['wsl', 'bash', '-lc', inner]
        return ['bash', '-lc', inner]

    def map_path(self, host_path: str) -> str:
        if not host_path:
            return host_path
        host_path = os.path.realpath(os.path.abspath(host_path))
        if self.backend == 'wsl':
            p = host_path.replace('\\', '/')
            if len(p) >= 2 and p[1] == ':':
                p = f'/mnt/{p[0].lower()}{p[2:]}'
            return p
        if self.backend == 'docker-amd64':
            for host_dir, container_dir in self.mounts:
                try:
                    if os.path.commonpath([host_path, host_dir]) == host_dir:
                        rel = os.path.relpath(host_path, host_dir)
                        return os.path.join(container_dir, rel).replace(os.sep, '/')
                except ValueError:
                    continue
            return '/host/' + os.path.basename(host_path)
        return host_path

    def inner_solver_command(self, binary: str, extra_args: Sequence[str] = ()) -> str:
        mapped_binary = shlex.quote(self.map_path(binary))
        solver = '/pwnsolver/pwn_solver/solver.py' if self.backend == 'docker-amd64' else str(SOLVER_SCRIPT)
        quoted = ' '.join(shlex.quote(str(x)) for x in extra_args)
        return f'python3 -W ignore {shlex.quote(solver)} {mapped_binary} {quoted}'.rstrip()


class RuntimeRouter:
    def __init__(self):
        self.os_name = platform.system()
        self.machine = platform.machine().lower()
        self.docker_ok, self.docker_err = self._probe_docker()
        self.wsl_ok, self.wsl_err = self._probe_wsl()

    def _probe_docker(self):
        if shutil.which('docker') is None:
            return False, 'docker not found'
        try:
            r = subprocess.run(['docker', 'info'], capture_output=True, text=True, timeout=15)
            return r.returncode == 0, ('' if r.returncode == 0 else r.stderr.strip()[:120])
        except Exception as exc:
            return False, str(exc)

    def _probe_wsl(self):
        if self.os_name != 'Windows':
            return False, 'not windows'
        if shutil.which('wsl') is None:
            return False, 'wsl not found'
        try:
            r = subprocess.run(['wsl', 'echo', 'ok'], capture_output=True, text=True, timeout=15)
            return r.returncode == 0, ('' if r.returncode == 0 else r.stderr.strip()[:120])
        except Exception as exc:
            return False, str(exc)

    def image_ready(self) -> bool:
        if not self.docker_ok:
            return False
        try:
            r = subprocess.run(['docker', 'image', 'inspect', X86_IMAGE],
                               capture_output=True, text=True, timeout=15)
            return r.returncode == 0
        except Exception:
            return False

    def _docker_plan(self, binary: str, libc: str = '', ld: str = '', reason: str = '',
                     mandatory: bool = True) -> RuntimePlan:
        mounts: List[Tuple[str, str]] = []
        dirs: List[str] = []
        root = os.path.realpath(str(PROJECT_ROOT))
        for p in (binary, libc, ld):
            if not p:
                continue
            d = os.path.realpath(os.path.dirname(os.path.abspath(p)))
            if d in dirs or d == root:
                continue
            dirs.append(d)
            mounts.append((d, f'/ctf{len(mounts)}'))
        if all(os.path.realpath(h) != root for h, _ in mounts):
            mounts.append((root, '/pwnsolver'))
        workdir = mounts[0][1] if mounts else '/pwnsolver'
        return RuntimePlan(backend='docker-amd64', host_os=self.os_name, host_arch=self.machine,
                           image=X86_IMAGE, mounts=mounts, workdir=workdir,
                           reason=reason or 'unified x86_64 Linux sandbox', mandatory=mandatory)

    def _wsl_plan(self, binary: str, libc: str = '', ld: str = '', reason: str = '') -> RuntimePlan:
        return RuntimePlan(backend='wsl', host_os=self.os_name, host_arch=self.machine,
                           reason=reason or 'WSL2 fallback')

    def plan(self, binary: str, libc: str = '', ld: str = '') -> RuntimePlan:
        target_arch = self._elf_arch(binary)
        need_x86 = target_arch in ('i386', 'x86', 'amd64', 'x86_64', 'x86-64')

        if self.os_name == 'Darwin':
            if self.machine in ('arm64', 'aarch64'):
                return self._docker_plan(binary, libc, ld,
                                         reason='Apple Silicon 强制使用 linux/amd64 容器执行实际题目',
                                         mandatory=True)
            if need_x86 and self.docker_ok:
                return self._docker_plan(binary, libc, ld,
                                         reason='Intel macOS 优先容器以获得完整工具链')
            return RuntimePlan(backend='native', host_os=self.os_name, host_arch=self.machine,
                               reason='Intel macOS 本机执行（非 x86 ELF 或 Docker 不可用）')

        if self.os_name == 'Linux':
            if need_x86 and self.machine in ('arm64', 'aarch64'):
                return self._docker_plan(binary, libc, ld,
                                         reason='Linux arm64 执行 x86 ELF 必须使用 linux/amd64 容器',
                                         mandatory=True)
            if need_x86 and os.environ.get('PWNSOLVER_FORCE_DOCKER') == '1':
                return self._docker_plan(binary, libc, ld, reason='PWNSOLVER_FORCE_DOCKER=1')
            return RuntimePlan(backend='native', host_os=self.os_name, host_arch=self.machine,
                               reason='Linux x86_64 本机执行（统一容器可设 PWNSOLVER_FORCE_DOCKER=1）')

        if self.os_name == 'Windows':
            if self.docker_ok:
                return self._docker_plan(binary, libc, ld,
                                         reason='Windows 使用 Docker Desktop linux/amd64 容器')
            if self.wsl_ok:
                return self._wsl_plan(binary, libc, ld, reason='Docker 不可用，回退 WSL2')
            return RuntimePlan(backend='error', host_os=self.os_name, host_arch=self.machine,
                               reason='Windows 需要 Docker Desktop 或 WSL2，且当前均不可用')

        return RuntimePlan(backend='native', host_os=self.os_name, host_arch=self.machine,
                           reason='未知平台，尝试本机执行')

    def _elf_arch(self, binary: str) -> str:
        if not binary or not os.path.exists(binary):
            return 'unknown'
        try:
            with open(binary, 'rb') as f:
                if f.read(4) != b'\x7fELF':
                    return 'non-elf'
                f.seek(18)
                machine = int.from_bytes(f.read(2), 'little')
                return {3: 'i386', 62: 'amd64', 183: 'aarch64', 40: 'arm'}.get(machine, f'elf-{machine}')
        except Exception:
            return 'unknown'

    def status(self) -> Dict[str, object]:
        return {
            'os': self.os_name,
            'arch': self.machine,
            'docker': self.docker_ok,
            'docker_error': self.docker_err,
            'wsl': self.wsl_ok,
            'wsl_error': self.wsl_err,
            'image': X86_IMAGE,
            'image_ready': self.image_ready(),
        }

    def describe(self) -> str:
        if self.os_name == 'Darwin':
            return 'macOS -> linux/amd64 Docker sandbox (mandatory)'
        if self.os_name == 'Windows' and self.docker_ok:
            return 'Windows -> Docker Desktop linux/amd64 sandbox'
        if self.os_name == 'Windows' and self.wsl_ok:
            return 'Windows -> WSL2'
        if self.os_name == 'Linux':
            if self.machine in ('arm64', 'aarch64'):
                return 'Linux ARM64 -> x86 ELF goes linux/amd64 Docker'
            return 'Linux x86_64 -> native'
        return f'{self.os_name}/{self.machine} -> native'
