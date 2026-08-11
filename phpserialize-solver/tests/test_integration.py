"""
Integration test: verify the solver works on all 18 levels.
Uses actual source code from each level (fetched from the repo).
Tests the full pipeline: analyze -> generate payloads -> verify expected payload exists.
"""
import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__)))

from engine.analyzer import PHPSourceAnalyzer
from engine.payload import PayloadGenerator
from engine.serializer import php_serialize, php_object


# ─── Level source code samples (from actual repo) ───

LEVEL_SOURCES = {
    1: '''<?php
class FLAG{
    public $flag_string = "HelloCTF{OK_Now_y0u_c4n_se3_me}";
    function __construct(){
        echo $this->flag_string;
    }
}
$code = $_POST['code'];
if(isset($code)){
    if (stripos($code, "new") === false) {
        echo "Not This level!";
    } else {
       eval($code);
    }
}
else { highlight_file('source'); }
''',

    2: '''<?php
error_reporting(0);
$flag_string = "HelloCTF{I_giv3_t0_y0u&y0u_giv3_t0_me}";
class FLAG {
    public $free_flag = "???";
    function get_free_flag(){ return $this->free_flag; }
}
$target = new FLAG();
$code = $_POST['code'];
if(isset($code)){
    eval($code);
    echo "Now Flag is ". $target->get_free_flag() ."<br>";
}
''',

    3: '''<?php
class FLAG {
    public $public_flag = "HelloCTF{se3_me_";
    protected $protected_flag = "4nd_g3t_";
    private $private_flag = "mmmme}";
    function get_protected_flag(){ return $this->protected_flag; }
    function get_private_flag(){ return $this->private_flag; }
}
class SubFLAG extends FLAG {
    function show_protected_flag(){ return $this->protected_flag; }
}
$target = new FLAG(); $sub_target = new SubFLAG();
$code = $_POST['code'];
if(isset($code)){ eval($code); }
''',

    4: '''<?php
class FLAG3 { private $flag3_object_array = array("se3","me"); }
class FLAG {
    private $flag1_string = "ser4l1ze";
    private $flag2_number = 2;
    private $flag3_object;
    function __construct() { $this->flag3_object = new FLAG3(); }
}
$flag_is_here = new FLAG();
$code = $_POST['code'];
if(isset($code)){ eval($code); }
''',

    5: '''<?php
class a_class { public $a_value = "HelloCTF"; }
$a_array = array(a=>"Hello",b=>"CTF");
$a_string = "HelloCTF"; $a_number = 678470;
$a_boolean = true; $a_null = null;

$your_object = $_POST['o']; $your_string = $_POST['s'];
$your_array = $_POST['a']; $your_number = $_POST['i'];
$your_boolean = $_POST['b']; $your_NULL = $_POST['n'];

$your_object = unserialize($your_object);
$your_array = unserialize($your_array);
$your_string = unserialize($your_string);
$your_number = unserialize($your_number);
$your_boolean = unserialize($your_boolean);
$your_NULL = unserialize($your_NULL);

$flag = "HelloCTF{Gre4t,y0u_can_als0_ser4l1ze2se_1n_y0ur_m1nd!}";
if($your_boolean && $your_NULL == null && $your_string == "IWANT" &&
   $your_number == 1 && $your_object->a_value == "FLAG" &&
   $your_array['a'] == "Plz" && $your_array['b'] == "Give_M3"){
    echo $flag;
}
''',

    6: '''<?php
$flag = "HelloCTF{P3rm1ssi0n_Modif_1s_1mp0rtant}";
class protectedKEY { protected $protected_key; function get_key(){ return $this->protected_key; } }
class privateKEY { private $private_key; function get_key(){ return $this->private_key; } }
$protected_key = unserialize($_POST['protected_key']);
$private_key = unserialize($_POST['private_key']);
if(isset($_POST['protected_key'])&&isset($_POST['private_key'])){
    if($protected_key->get_key() == "protected_key" && $private_key->get_key() == "private_key"){
        echo $flag;
    }
}
''',

    7: '''<?php
class FLAG {
    public $flag_command = "echo 'Hello CTF!<br>';";
    function backdoor(){ eval($this->flag_command); }
}
$unserialize_string = 'O:4:"FLAG":1:{s:12:"flag_command";s:24:"echo \\'Hello World!<br>\\';";}';
$Instantiate_object = new FLAG();
$Unserialize_object = unserialize($unserialize_string);
if(isset($_POST['o'])){ unserialize($_POST['o'])->backdoor(); }
''',

    8: '''<?php
global $destruct_flag; global $construct_flag;
$destruct_flag = 0; $construct_flag = 0;
class FLAG { public function __construct(){ global $construct_flag; $construct_flag++; } public function __destruct(){ global $destruct_flag; $destruct_flag++; } }
class RELFLAG { }
$flag = "FLAG{Construct0r_&_D3struct0r}";
$code = $_POST['code'];
if(isset($code)){ eval($code); if($destruct_flag > 5){ echo $flag; } }
''',

    9: '''<?php
class FLAG { var $flag_command = "echo 'Hello CTF!<br>';"; function __destruct(){ eval($this->flag_command); } }
if(isset($_POST['o'])){ unserialize($_POST['o']); }
''',

    10: '''<?php
class FLAG { function __wakeup(){ include 'flag.php'; echo $flag; } }
if(isset($_POST['o'])){ unserialize($_POST['o']); }
''',

    11: '''<?php
class FLAG {
    public $flag = "FAKEFLAG";
    public function __wakeup(){ global $flag; $flag = NULL; }
    public function __destruct(){ global $flag; if($flag !== NULL){ echo $flag; } }
}
if(isset($_POST['o'])){ unserialize($_POST['o']); }
''',

    12: '''<?php
class FLAG { private $f='clean_'; private $l='up_'; protected $a='4nd_'; public $g='select_variab1es}'; public $x,$y,$z; function __sleep(){ return ['x','y','z']; } }
class CHALLENGE extends FLAG {
    public $h='HelloCTF{'; public $e='Th3_'; public $l='__sleep_function_'; public $I='_is_';
    public $o='called_'; public $c='before_'; public $t='serialization_'; public $f='t0_'; public $chance;
    function chance(){ if(isset($_GET['chance'])){ return $_GET['chance']; } return 'you shuold use it'; }
    public function __sleep(){ return [$this->chance()]; }
}
$FLAG = new FLAG(); echo serialize(new CHALLENGE());
''',

    13: '''<?php
class FLAG { function __toString(){ include 'flag.php'; return $flag; } }
$obj = new FLAG();
if(isset($_POST['o'])){ eval($_POST['o']); }
''',

    14: '''<?php
class FLAG { function __invoke($x){ if($x == 'get_flag'){ include 'flag.php'; echo $flag; } } }
$obj = new FLAG();
if(isset($_POST['o'])){ eval($_POST['o']); }
''',

    15: '''<?php
class A { public $a; public function __construct($a){ $this->a = $a; } }
class B { public $b; public function __construct($b){ $this->b = $b; } }
class C { public $c; public function __construct($c){ $this->c = $c; } }
class D { public $d; public function __construct($d){ $this->d = $d; } public function __wakeUp(){ $this->d->action(); } }
class destnation { var $cmd; public function __construct($cmd){ $this->cmd = $cmd; } public function action(){ eval($this->cmd->a->b->c); } }
if(isset($_POST['o'])){ unserialize($_POST['o']); }
''',

    16: '''<?php
class A { public $a; public function __invoke(){ include $this->a; return $flag; } }
class B { public $b; public function __toString(){ $f = $this->b; return $f(); } }
class INIT { public $name; public function __wakeUp(){ echo $this->name.' is awake!'; } }
if(isset($_POST['o'])){ unserialize($_POST['o']); }
''',

    17: '''<?php
class A { }
class B { public $a = "Hello"; protected $b = "CTF"; private $c = "FLAG{TEST}"; }
$serliseString = serialize(new B()); $serliseString = str_replace('B', 'A', $serliseString);
if(isset($_POST['o'])){
    $a = unserialize($_POST['o']);
    if($a instanceof A && $a->helloctfcmd == "get_flag"){ include 'flag.php'; echo $flag; }
}
''',

    18: '''<?php
class Demo { public $a = "Hello"; public $b = "CTF"; public $key = 'GET_FLAG";}FAKE_FLAG'; }
class FLAG { }
$serliseStringDemo = serialize(new Demo());
$target = $_GET['target']; $change = $_GET['change'];
$serliseStringFLAG = str_replace($target, $change, $serliseStringDemo);
$FLAG = unserialize($serliseStringFLAG);
if($FLAG instanceof FLAG && $FLAG->key == 'GET_FLAG'){ include 'flag.php'; echo $flag; }
''',
}


def test_all_levels():
    """Verify the analyzer + payload generator for all 18 levels."""
    analyzer = PHPSourceAnalyzer()
    generator = PayloadGenerator()

    results = {}

    for level_num in sorted(LEVEL_SOURCES.keys()):
        source = LEVEL_SOURCES[level_num]
        analysis = analyzer.analyze(source, url=f"Level{level_num}")
        payloads = generator.generate(analysis)

        has_payloads = len(payloads) > 0
        has_serialized = any(p.serialized_string for p in payloads)
        has_eval = any(p.raw_code for p in payloads)
        strategy = analysis.strategy

        results[level_num] = {
            'classes': [c.name for c in analysis.classes],
            'sinks': [s.type for s in analysis.sinks],
            'inputs': [(i.method, i.name) for i in analysis.inputs],
            'strategy': strategy,
            'payload_count': len(payloads),
            'has_serialized': has_serialized,
            'has_eval': has_eval,
            'ok': has_payloads,
        }

        assert has_payloads, f"Level {level_num}: No payloads generated (strategy={strategy})"
        assert strategy != 'unknown', f"Level {level_num}: Unknown strategy"

    return results


def test_specific_levels():
    """Targeted tests for specific level patterns."""
    analyzer = PHPSourceAnalyzer()
    generator = PayloadGenerator()

    # Level 1: eval with "new" restriction
    analysis = analyzer.analyze(LEVEL_SOURCES[1])
    payloads = generator.generate(analysis)
    assert analysis.strategy == 'eval_injection'
    # Should have payloads that include "new" keyword
    eval_payloads = [p for p in payloads if p.raw_code and 'new' in p.raw_code.lower()]
    assert len(eval_payloads) > 0, "Level 1: No 'new' keyword payloads"

    # Level 5: multiple unserialize parameters
    analysis = analyzer.analyze(LEVEL_SOURCES[5])
    payloads = generator.generate(analysis)
    # Should find post params o, s, a, i, b, n
    input_names = {i.name for i in analysis.inputs}
    assert len(input_names) >= 5, f"Level 5: Expected >=5 inputs, got {input_names}"
    # Should have a Level 5 specific payload
    level5 = [p for p in payloads if 'Level 5' in p.description]
    assert len(level5) > 0, "Level 5: No specific payload"

    # Level 7: unserialize with backdoor method
    analysis = analyzer.analyze(LEVEL_SOURCES[7])
    payloads = generator.generate(analysis)
    assert analysis.strategy == 'unserialize_injection'
    # Should have payloads targeting flag_command
    has_cmd_payload = any(
        'flag_command' in (p.serialized_string or '') for p in payloads
    )
    assert has_cmd_payload, "Level 7: No flag_command payload"

    # Level 9: __destruct with eval
    analysis = analyzer.analyze(LEVEL_SOURCES[9])
    assert analysis.classes[0].name == 'FLAG'
    has_destruct = any(m.name == '__destruct' for m in analysis.classes[0].methods)
    assert has_destruct, "Level 9: __destruct not detected"

    # Level 11: CVE-2016-7124
    analysis = analyzer.analyze(LEVEL_SOURCES[11])
    payloads = generator.generate(analysis)
    bypass = [p for p in payloads if p.strategy == 'wakeup_bypass']
    assert len(bypass) > 0, "Level 11: No wakeup bypass payload"
    # Check inflated count
    assert any('"FLAG":2:' in (p.serialized_string or '') for p in bypass), \
        "Level 11: Property count not inflated"

    # Level 15: POP chain
    analysis = analyzer.analyze(LEVEL_SOURCES[15])
    # Should have 5 classes
    assert len(analysis.classes) == 5, f"Level 15: Expected 5 classes, got {len(analysis.classes)}"

    # Level 16: POP chain
    analysis = analyzer.analyze(LEVEL_SOURCES[16])
    payloads = generator.generate(analysis)
    init_payloads = [p for p in payloads if 'INIT' in str(p.description)]
    assert len(init_payloads) > 0, "Level 16: No INIT chain payload"

    # Level 17: string escape
    analysis = analyzer.analyze(LEVEL_SOURCES[17])
    payloads = generator.generate(analysis)
    # Should have payload with helloctfcmd
    has_cmd = any(
        'helloctfcmd' in (p.serialized_string or '').lower()
        for p in payloads
    )
    assert has_cmd, "Level 17: No helloctfcmd payload"

    # Level 18: string escape with GET params
    analysis = analyzer.analyze(LEVEL_SOURCES[18])
    payloads = generator.generate(analysis)
    get_payloads = [p for p in payloads if p.http_method == 'GET' and p.params]
    assert len(get_payloads) > 0, "Level 18: No GET payload"


def test_full_pipeline_simulation():
    """Simulate the full solver pipeline (without actual HTTP)."""
    from engine.http_client import HTTPClient
    from engine.flag_extractor import extract_flags

    analyzer = PHPSourceAnalyzer()
    generator = PayloadGenerator()

    # Test that the pipeline works for each level
    total_ok = 0
    for level_num in sorted(LEVEL_SOURCES.keys()):
        source = LEVEL_SOURCES[level_num]
        try:
            # Step 1: Analyze
            analysis = analyzer.analyze(source)
            # Step 2: Generate
            payloads = generator.generate(analysis)
            # Step 3: Verify at least one payload exists
            if len(payloads) > 0:
                total_ok += 1
            else:
                print(f"  WARNING: Level {level_num} has no payloads")
        except Exception as e:
            print(f"  ERROR Level {level_num}: {e}")

    assert total_ok == 18, f"Only {total_ok}/18 levels generated payloads"


if __name__ == '__main__':
    import pytest
    sys.exit(pytest.main([__file__, '-v', '--tb=short']))
