"""Verify tool behavior on non-deserialization challenges (ctf.show upload)."""
import sys
sys.path.insert(0, '.')

from engine.analyzer import PHPSourceAnalyzer
from engine.payload import PayloadGenerator

SOURCE = r"""<?php
error_reporting(0);
highlight_file(__FILE__);
$finfo = finfo_open(FILEINFO_MIME_TYPE);
if (finfo_file($finfo, $_FILES['file']['tmp_name']) === 'application/zip'){
    exec('cd /tmp && unzip -o ' . $_FILES['file']['tmp_name']);
};
"""


def test_ctfshow_upload_analysis():
    """Tool should correctly identify this as non-deserialization."""
    analyzer = PHPSourceAnalyzer()
    result = analyzer.analyze(SOURCE, url='upload.php')

    # No PHP classes — not a deserialization challenge
    assert len(result.classes) == 0

    # Should find the exec sink
    assert any(s.type == 'exec' for s in result.sinks)

    # No POST/GET inputs (only $_FILES which we don't track)
    post_get_inputs = [i for i in result.inputs if i.method in ('POST', 'GET')]
    assert len(post_get_inputs) == 0

    # Strategy should be unknown — tool knows it can't handle this
    assert result.strategy == 'unknown'


def test_ctfshow_upload_payloads_irrelevant():
    """Generated payloads should be marked as generic fallbacks, not targeted."""
    analyzer = PHPSourceAnalyzer()
    result = analyzer.analyze(SOURCE)
    generator = PayloadGenerator()
    payloads = generator.generate(result)

    # Tool generates fallback payloads but they won't work
    # (all assume POST 'code' or 'o' params, none use $_FILES)
    assert all('code' in p.data or 'o' in p.data for p in payloads if p.data)
    # None of the payloads are for file upload
    assert not any('FILES' in str(p.data) for p in payloads)


if __name__ == '__main__':
    import pytest
    sys.exit(pytest.main([__file__, '-v']))
