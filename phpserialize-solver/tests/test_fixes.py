"""Verify Level 5/6/2 fixes."""
import sys; sys.path.insert(0, '.')
from engine.analyzer import PHPSourceAnalyzer
from engine.payload import PayloadGenerator

def test_l5_no_phantom_property():
    src = ('<?php\n    class secret{\n        var $file="index.php";\n'
           '        function __destruct(){\n            include_once($this->file);\n'
           '            echo $flag;\n        }\n'
           '        function __wakeup(){\n            $this->file="index.php";\n        }\n    }\n'
           '    $cmd=$_GET["cmd"];\n'
           '    if(preg_match(\'/[oc]:\\d+:/i\',$cmd)){ echo "no"; }\n'
           '    else{ unserialize($cmd); }\n?>')
    a = PHPSourceAnalyzer()
    r = a.analyze(src)
    props = r.classes[0].properties
    # Should Only have 'file', NOT 'flag'
    names = [p.name for p in props]
    assert 'file' in names, f"Expected 'file' in {names}"
    assert 'flag' not in names, f"BUG: phantom 'flag' property found in {names}"

def test_l6_string_escape_payloads():
    from engine.serializer import php_unserialize
    src = ('<?php\nclass secret{\n    private $comm;\n'
           '    function __destruct(){ echo eval($this->comm); }\n}\n'
           '$param=$_GET["param"];\n'
           '$param=str_replace("%","daydream",$param);\n'
           'unserialize($param);\n?>')
    a = PHPSourceAnalyzer()
    r = a.analyze(src)
    assert r.strategy == 'string_escape'
    g = PayloadGenerator()
    ps = g.generate(r)
    assert len(ps) > 0, "Level 6: No string escape payloads generated!"
    # Verify payload structure (valid after server-side str_replace)
    for p in ps:
        if p.serialized_string:
            assert p.serialized_string.startswith('O:'), f"Not valid: {p.serialized_string[:50]}"
            # Raw payload is intentionally invalid — becomes valid after str_replace on server
            assert '%' in p.serialized_string, "Padding % chars should be inside value"
            # Verify declared length matches n * len(replace_str) for proper expansion
            import re
            len_matches = re.findall(r's:(\d+):"', p.serialized_string)
            if len(len_matches) >= 2:
                comm_len = int(len_matches[1])  # the padded value length
                n_pct = p.serialized_string.count('%')
                # declared length should = n * 8 (after %→daydream expansion)
                assert comm_len == n_pct * 8, \
                    f"Declared length {comm_len} != {n_pct}*8 (will break after expansion)"

def test_l2_condition_parsing():
    src = ('<?php\nclass mylogin{\n    var $user;\n    var $pass;\n'
           '    function login(){\n        if ($this->user=="daydream" and $this->pass=="ok"){\n'
           '            return 1;\n        }\n    }\n}\n'
           '$a=unserialize($_GET["param"]);\nif($a->login()){ echo $flag; }\n?>')
    a = PHPSourceAnalyzer()
    r = a.analyze(src)
    g = PayloadGenerator()
    ps = g.generate(r)
    # Check that payload has correct values from condition parsing
    assert len(ps) > 0
    for p in ps:
        if p.serialized_string:
            assert 'daydream' in p.serialized_string, f"Expected 'daydream' from condition, got: {p.serialized_string[:100]}"
            assert '"ok"' in p.serialized_string or "'ok'" in p.serialized_string, f"Expected 'ok' from condition"

if __name__ == '__main__':
    import pytest; sys.exit(pytest.main([__file__, '-v']))
