# reverse-skill 集成测试（不依赖 pwntools，可在宿主机直接运行）
import os
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'pwn_solver'))


def test_library_discovers_vendored_skills():
    from reverse_skill import SkillLibrary
    lib = SkillLibrary()
    ids = {d.skill_id for d in lib.list_skills()}
    assert {'pwn-chain', 'reverse-engineering', 'radare2',
            'ghidra-reverse', 'go-rust-reverse',
            'competition-reverse-pwn'} <= ids
    assert lib.get('pwn') is not None
    assert lib.get('r2') is not None
    assert len(lib.list_references()) >= 5


def test_router_prefers_pwn_chain_and_re_for_stripped_target():
    from reverse_skill import PwnSkillRouter, SkillLibrary
    lib = SkillLibrary()
    hits = PwnSkillRouter(lib).route({
        'vuln_type': 'ret2libc',
        'functions': {'stripped': True},
        'protections': {'nx': True, 'pie': True, 'canary': True},
        'info': {'type': 'ELF', 'arch': 'amd64'},
        'reverse_intel': {},
    })
    assert hits, 'expected non-empty route result'
    assert hits[0].doc.skill_id == 'pwn-chain'
    ids = [h.doc.skill_id for h in hits]
    assert 'reverse-engineering' in ids
    assert 'radare2' in ids


def test_playbook_builder_generates_actionable_markdown():
    from reverse_skill import PlaybookBuilder, SkillLibrary
    analysis = {
        'info': {'type': 'ELF', 'arch': 'amd64', 'binary_path': '/ctf/vuln'},
        '_binary_path': '/ctf/vuln',
        '_libc_path': '/ctf/libc.so.6',
        '_vuln_type': 'ret2libc',
        'protections': {'nx': True, 'pie': True, 'canary': True},
        'functions': {
            'stripped': True,
            'dangerous': [('plt.read', '0x4010')],
        },
        'buffers': [],
        'reverse_intel': {
            'packed': {'packed': False},
            'language': {'go': False, 'rust': False},
            'anti_analysis': {'anti_analysis': False, 'seccomp': False},
        },
    }
    gadgets = {'plt': {'puts': '0x401020'}, 'one_gadgets': [], 'pop_rdi_in_binary': True}
    pb = PlaybookBuilder(SkillLibrary()).build(analysis, gadgets)
    assert pb['routes'][0]['id'] == 'pwn-chain'
    assert any('远程稳定化' in x for x in pb['checklist'])
    assert any('PIE 开启' in x for x in pb['checklist'])
    assert 'ret2libc' in pb['vuln_type']
    assert '# PwnSolver × reverse-skill Playbook' in pb['markdown']
    assert 'pwn-chain' in pb['markdown']


def test_tool_probe_reports_missing_without_crashing():
    from reverse_skill import ToolProbe
    tp = ToolProbe()
    status = tp.check()
    assert 'pwntools' in status
    assert isinstance(tp.missing(), list)
    assert isinstance(tp.render_markdown(), str)
    # 所有状态都必须有安装建议
    for item in status.values():
        assert item.get('install')


def test_deep_recon_runs_without_pwntools_and_writes_evidence():
    from deep_recon import DeepRecon
    target = sys.executable  # 任意可执行文件，验证 triage 流程
    with tempfile.TemporaryDirectory() as tmp:
        recon = DeepRecon(target, workdir=tmp, verbose=False, run_r2_analysis=True)
        result = recon.run()
        assert len(result['sha256']) == 64
        assert result['file_type']
        assert isinstance(result['info'], dict)
        assert isinstance(result['tooling'], dict)
        assert 'anti_analysis' in result

        evidence = recon.write_evidence(result)
        assert Path(evidence['json']).exists()
        assert Path(evidence['markdown']).exists()
        text = Path(evidence['markdown']).read_text(encoding='utf-8')
        assert 'Recon Evidence' in text

        # 若环境有 r2，--deep-r2 应产出函数级证据
        r2_status = (result.get('tooling') or {}).get('status', {}).get('r2', {})
        if r2_status.get('ok'):
            assert result.get('r2_functions'), '--deep-r2 should populate r2_functions'


def test_skill_search_and_sections():
    from reverse_skill import SkillLibrary
    lib = SkillLibrary()
    results = lib.search('libc')
    assert results
    stack = lib.get('skills-pwn-chain-references-stack-pwn')
    assert stack is not None
    sections = stack.sections()
    assert any('ret2libc' in k for k in sections.keys())


if __name__ == '__main__':
    import traceback
    tests = [v for k, v in globals().items() if k.startswith('test_')]
    failed = 0
    for test in tests:
        try:
            test()
            print(f'PASS {test.__name__}')
        except Exception as exc:
            failed += 1
            print(f'FAIL {test.__name__}: {exc}')
            traceback.print_exc()
    sys.exit(1 if failed else 0)
