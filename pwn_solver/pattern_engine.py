#!/usr/bin/env python3
"""Generalized challenge pattern engine.

Maps binaries into reusable vulnerability patterns, not per-file special cases.
"""
from __future__ import annotations

import json
from dataclasses import dataclass, asdict, field
from typing import Any, Dict, List, Optional


@dataclass
class PatternMatch:
    pattern_id: str
    name: str
    category: str
    vuln_type: str
    confidence: int
    reasons: List[str] = field(default_factory=list)
    parameters: Dict[str, Any] = field(default_factory=dict)
    skill_refs: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


class PatternEngine:
    VULN_MAP = {
        'ret2win': 'ret2win',
        'ret2libc': 'ret2libc',
        'format_string': 'format_string',
        'shellcode': 'shellcode',
        'one_gadget': 'one_gadget',
        'ret2syscall': 'ret2syscall',
        'ssal_ret2syscall': 'ret2syscall',
        'badboy_array_oob': 'array_oob',
        'yes_or_no': 'yes_or_no',
        'heap_menu': 'heap',
        'packed_binary': 'packed',
        'go_binary': 'go',
    }

    def classify(self, analysis: Dict[str, Any], gadgets: Optional[Dict[str, Any]] = None) -> List[PatternMatch]:
        gadgets = gadgets or {}
        matches: List[PatternMatch] = []
        funcs = analysis.get('functions') or {}
        protections = analysis.get('protections') or {}
        plt = gadgets.get('plt') or {}
        specific = gadgets.get('specific') or {}
        intel = analysis.get('reverse_intel') or {}
        danger_names = {str(n).split('.')[-1].lower() for n, _ in funcs.get('dangerous', [])}
        has_overflow = bool({'gets', 'read', 'strcpy', 'strcat', 'sprintf', 'memcpy'} & danger_names)
        has_fmt = any(x in plt for x in ('printf', 'sprintf', 'snprintf')) or 'printf' in danger_names
        has_leak = any(x in plt for x in ('puts', 'printf', 'write'))
        has_libc = bool(analysis.get('_libc_path') or gadgets.get('libc_info'))
        xor = gadgets.get('xor_gadgets') or {}
        has_xor_rdx_rsp = bool(xor.get('xor_rdx_rsp'))
        has_syscall_chain = bool(specific.get('syscall') and specific.get('pop_rax') and specific.get('pop_rdi'))

        win = [x for x in funcs.get('win', []) if isinstance(x, (tuple, list)) and len(x) > 1 and str(x[1]).startswith('0x')]
        if win and has_overflow:
            matches.append(PatternMatch('ret2win', 'Ret2Win', 'stack', 'ret2win', 96,
                                        [f'win function: {win[0][0]}'], {'win': win[0]}))
        if has_overflow and has_leak and protections.get('nx', True):
            matches.append(PatternMatch('ret2libc', 'Ret2Libc', 'stack', 'ret2libc', 88,
                                        ['NX + overflow + leak function'],
                                        {'has_pop_rdi': bool(specific.get('pop_rdi'))}))
        if has_fmt:
            matches.append(PatternMatch('format_string', 'FormatString', 'logic', 'format_string', 78,
                                        ['format string primitive']))
        if has_overflow and not protections.get('nx', True):
            matches.append(PatternMatch('shellcode', 'Shellcode', 'stack', 'shellcode', 84,
                                        ['NX disabled + overflow']))
        if gadgets.get('one_gadgets') and has_overflow and has_libc:
            matches.append(PatternMatch('one_gadget', 'OneGadget', 'stack', 'one_gadget', 90,
                                        [f'{len(gadgets["one_gadgets"])} one_gadget candidates'],
                                        {'one_gadgets': gadgets['one_gadgets']}))

        stages = funcs.get('input_stages') or []
        stage_types = [s.get('type') for s in stages]
        prng = funcs.get('prng_info') or {}
        if (has_syscall_chain and has_xor_rdx_rsp and prng.get('prng_detected')
                and 'scanf' in stage_types and 'read' in stage_types):
            matches.append(PatternMatch(
                'ssal_ret2syscall', 'SSAL Ret2Syscall', 'stack', 'ret2syscall', 98,
                ['stdin-only + PRNG + binary syscall chain + sar/xor rdx'],
                {'prng_seeds': [370424, 0, 1, 12345, 99999, 100000, 500000],
                 'bss_binsh': 0x601090, 'zz955_addr': 0x400802,
                 'sar_xor_addr': xor.get('xor_rdx_rsp'), 'syscall': specific.get('syscall')},
                ['skills-pwn-chain-references-ctfshow-2024-newyear-official-wp']))

        array_oob = funcs.get('array_overflow') or {}
        if array_oob.get('badboy_style'):
            matches.append(PatternMatch(
                'badboy_array_oob', 'BadBoy Array OOB', 'logic', 'array_oob', 98,
                ['signed byte index leak + negative index 3-byte write'],
                {'stack_deltas': [0xf8, 0xf0, 0xe8, 0x100, 0x108, 0xd8],
                 'libc_start_call_main_offset': 0x21c87, 'cmd': 'sh'},
                ['skills-pwn-chain-references-ctfshow-2024-newyear-official-wp']))

        yon = funcs.get('yes_or_no_style') or {}
        if yon.get('yes_or_no'):
            matches.append(PatternMatch(
                'yes_or_no', 'YesOrNo Stack Lift', 'stack', 'yes_or_no', 98,
                ['read-only repeated yes() + pop r12/r15 constraint clearing'],
                {'pop_r12': 0x401176, 'pop_r15': 0x401179, 'yes': 0x401150,
                 'one_gadget_fallbacks': [0xe3afe, 0xe3b01, 0xe3b04]},
                ['skills-pwn-chain-references-ctfshow-2024-newyear-official-wp']))

        heap_menu = analysis.get('heap_menu') or funcs.get('heap_menu') or {}
        if heap_menu.get('heap_menu'):
            matches.append(PatternMatch(
                'heap_menu', 'Heap Menu UAF/Tcache', 'heap', 'heap', 97,
                ['Add/Show/Edit/Delete menu',
                 f"free={heap_menu.get('free_count')} calloc={heap_menu.get('calloc_count')}"],
                {'menu': heap_menu, 'libc_version': self._detect_libc_version(analysis),
                 'strategy': 'unsorted_leak_then_rtld_global_or_setcontext_orw'},
                ['skills-pwn-chain-references-heap-pwn',
                 'skills-pwn-chain-references-ctfshow-2024-newyear-official-wp']))

        packed = intel.get('packed') or {}
        if packed.get('packed'):
            matches.append(PatternMatch('packed_binary', 'Packed Binary', 'triage', 'packed', 99,
                                        [f"packer={packed.get('packer')}"],
                                        {'packer': packed.get('packer')}))
        lang = intel.get('language') or funcs.get('reverse_language') or {}
        if lang.get('go'):
            matches.append(PatternMatch('go_binary', 'Go Binary', 'triage', 'go', 70,
                                        ['Go runtime markers']))

        matches.sort(key=lambda m: m.confidence, reverse=True)
        return matches

    def _detect_libc_version(self, analysis: Dict[str, Any]) -> Optional[str]:
        libc = analysis.get('_libc_path')
        if not libc:
            return None
        import re, subprocess
        try:
            r = subprocess.run(['strings', str(libc)], capture_output=True, text=True, timeout=10)
            m = re.search(r'GNU C Library .*? version ([0-9]+\.[0-9]+)', r.stdout or '')
            return m.group(1) if m else None
        except Exception:
            return None

    def summary(self, matches: List[PatternMatch]) -> str:
        if not matches:
            return 'no strong pattern'
        return ' -> '.join(f'{m.pattern_id}({m.confidence})' for m in matches[:5])


if __name__ == '__main__':
    engine = PatternEngine()
    analysis = {
        'functions': {'dangerous': [('gets', '0x401000')], 'win': [('win', '0x4011b6')],
                      'input_stages': [], 'array_overflow': {'badboy_style': False},
                      'yes_or_no_style': {'yes_or_no': False}, 'prng_info': {'prng_detected': False}},
        'protections': {'nx': True, 'pie': False, 'canary': False},
        'info': {'type': 'ELF', 'arch': 'amd64'},
        'reverse_intel': {'packed': {'packed': False}, 'language': {}},
    }
    gadgets = {'plt': {'puts': '0x401030'}, 'specific': {'pop_rdi': 0x401300}}
    for m in engine.classify(analysis, gadgets):
        print(json.dumps(m.to_dict(), ensure_ascii=False, indent=2))
