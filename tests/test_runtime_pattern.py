import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'pwn_solver'))


def _analysis(**overrides):
    base = {
        'functions': {
            'dangerous': [('gets', '0x401000')],
            'win': [],
            'input_stages': [],
            'array_overflow': {},
            'yes_or_no_style': {},
            'prng_info': {},
            'reverse_language': {},
        },
        'protections': {'nx': True, 'pie': False, 'canary': False},
        'info': {'type': 'ELF', 'arch': 'amd64'},
        'reverse_intel': {'packed': {'packed': False}, 'language': {}},
        '_libc_path': '/ctf/libc.so.6',
    }
    base.update(overrides)
    return base


def test_runtime_router_detects_platform_and_has_mapping_api():
    from runtime_router import RuntimeRouter
    r = RuntimeRouter()
    status = r.status()
    assert status['os'] in ('Darwin', 'Linux', 'Windows')
    assert 'docker' in status
    assert 'image' in status

    # 路径映射在 docker 计划中必须落在挂载目录内
    binary = '/tmp/pwnbench/vuln'
    plan = r.plan(binary, '/tmp/pwnbench/libc.so.6', '/tmp/pwnbench/ld-linux.so.2')
    if plan.backend == 'docker-amd64':
        mapped = plan.map_path(binary)
        assert mapped.startswith('/ctf'), mapped
        assert '/pwnsolver' in [c for _, c in plan.mounts]
        assert any('SYS_PTRACE' in x for x in plan.build_command('true'))
    else:
        assert plan.map_path(binary) == binary


def test_pattern_engine_badboy_yesorno_and_heap():
    from pattern_engine import PatternEngine
    engine = PatternEngine()

    badboy = _analysis(functions={
        'dangerous': [('read', '0x401000')],
        'win': [],
        'input_stages': [],
        'array_overflow': {'badboy_style': True},
        'yes_or_no_style': {},
        'prng_info': {},
    })
    ids = [m.pattern_id for m in engine.classify(badboy, {'plt': {}, 'specific': {}})]
    assert 'badboy_array_oob' in ids

    yon = _analysis(functions={
        'dangerous': [('read', '0x401000')],
        'win': [],
        'input_stages': [],
        'array_overflow': {},
        'yes_or_no_style': {'yes_or_no': True, 'clear_r12': True, 'clear_r15': True},
        'prng_info': {},
    })
    ids = [m.pattern_id for m in engine.classify(yon, {'plt': {}, 'specific': {}})]
    assert 'yes_or_no' in ids

    heap = _analysis(
        functions={'dangerous': [('read', '0x401000')], 'win': [], 'input_stages': [],
                   'array_overflow': {}, 'yes_or_no_style': {}, 'prng_info': {}},
        heap_menu={'heap_menu': True, 'free_count': 1, 'calloc_count': 2, 'scanf_count': 6},
    )
    ids = [m.pattern_id for m in engine.classify(heap, {'plt': {'free': '0x401000'}, 'specific': {}})]
    assert 'heap_menu' in ids


def test_pwnsolver_entrypoint_parses_commands():
    import ast
    src = (ROOT / 'pwnsolver.py').read_text(encoding='utf-8')
    ast.parse(src)
    assert 'runtime_router' in src


if __name__ == '__main__':
    for f in [test_runtime_router_detects_platform_and_has_mapping_api,
              test_pattern_engine_badboy_yesorno_and_heap,
              test_pwnsolver_entrypoint_parses_commands]:
        f()
        print('PASS', f.__name__)
