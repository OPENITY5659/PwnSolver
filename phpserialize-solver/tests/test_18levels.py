"""Batch test the tool against all 18 PHPSerialize-labs levels."""
import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from engine.analyzer import PHPSourceAnalyzer
from engine.payload import PayloadGenerator

# All 18 levels from PHPSerialize-labs
LEVELS = {}

LEVELS[1] = '''<?php class FLAG{public $flag_string="HelloCTF{OK_Now_y0u_c4n_se3_me}";function __construct(){echo $this->flag_string;}}
$code=$_POST['code'];if(isset($code)){if(stripos($code,"new")===false){echo "Not This level!";}else{eval($code);}}'''

LEVELS[2] = '''<?php error_reporting(0);$flag_string="HelloCTF{I_giv3_t0_y0u&y0u_giv3_t0_me}";
class FLAG{public $free_flag="???";function get_free_flag(){return $this->free_flag;}}$target=new FLAG();
$code=$_POST['code'];if(isset($code)){eval($code);echo "Now Flag is ".$target->get_free_flag()."<br>";}'''

LEVELS[3] = '''<?php
class FLAG{public $public_flag="HelloCTF{se3_me_";protected $protected_flag="4nd_g3t_";private $private_flag="mmmme}";
function get_protected_flag(){return $this->protected_flag;}function get_private_flag(){return $this->private_flag;}}
class SubFLAG extends FLAG{function show_protected_flag(){return $this->protected_flag;}}$target=new FLAG();$sub_target=new SubFLAG();
$code=$_POST['code'];if(isset($code)){eval($code);}'''

LEVELS[4] = '''<?php class FLAG3{private $flag3_object_array=array("se3","me");}
class FLAG{private $flag1_string="ser4l1ze";private $flag2_number=2;private $flag3_object;
function __construct(){$this->flag3_object=new FLAG3();}}$flag_is_here=new FLAG();$code=$_POST['code'];if(isset($code)){eval($code);}'''

LEVELS[5] = '''<?php class a_class{public $a_value="HelloCTF";}
$a_array=array(a=>"Hello",b=>"CTF");$a_string="HelloCTF";$a_number=678470;$a_boolean=true;$a_null=null;
$your_object=$_POST['o'];$your_string=$_POST['s'];$your_array=$_POST['a'];$your_number=$_POST['i'];$your_boolean=$_POST['b'];$your_NULL=$_POST['n'];
$your_object=unserialize($your_object);$your_array=unserialize($your_array);$your_string=unserialize($your_string);$your_number=unserialize($your_number);$your_boolean=unserialize($your_boolean);$your_NULL=unserialize($your_NULL);
$flag="HelloCTF{Gre4t,y0u_can_als0_ser4l1ze2se_1n_y0ur_m1nd!}";
if($your_boolean&&$your_NULL==null&&$your_string=="IWANT"&&$your_number==1&&$your_object->a_value=="FLAG"&&$your_array['a']=="Plz"&&$your_array['b']=="Give_M3"){echo $flag;}'''

LEVELS[6] = '''<?php $flag="HelloCTF{P3rm1ssi0n_Modif_1s_1mp0rtant}";
class protectedKEY{protected $protected_key;function get_key(){return $this->protected_key;}}
class privateKEY{private $private_key;function get_key(){return $this->private_key;}}
$protected_key=unserialize($_POST['protected_key']);$private_key=unserialize($_POST['private_key']);
if(isset($_POST['protected_key'])&&isset($_POST['private_key'])){if($protected_key->get_key()=="protected_key"&&$private_key->get_key()=="private_key"){echo $flag;}}'''

LEVELS[7] = '''<?php class FLAG{public $flag_command="echo 'Hello CTF!<br>';";function backdoor(){eval($this->flag_command);}}
if(isset($_POST['o'])){unserialize($_POST['o'])->backdoor();}'''

LEVELS[8] = '''<?php global $destruct_flag,$construct_flag;$destruct_flag=0;$construct_flag=0;
class FLAG{public function __construct(){global $construct_flag;$construct_flag++;}public function __destruct(){global $destruct_flag;$destruct_flag++;}}
class RELFLAG{public function __construct(){global $flag;$flag=0;$flag++;}public function __destruct(){global $flag;$flag++;}}
function check(){global $flag;if($flag>5){echo "FLAG{Construct0r_&_D3struct0r}";}}
if(isset($_POST['code'])){eval($_POST['code']);check();}'''

LEVELS[9] = '''<?php class FLAG{var $flag_command="echo 'HelloCTF';";public function __destruct(){eval($this->flag_command);}}
if(isset($_POST['o'])){unserialize($_POST['o']);}'''

LEVELS[10] = '''<?php error_reporting(0);class FLAG{function __wakeup(){include 'flag.php';echo $flag;}}
if(isset($_POST['o'])){unserialize($_POST['o']);}'''

LEVELS[11] = '''<?php error_reporting(0);include 'flag.php';
class FLAG{public $flag="FAKEFLAG";public function __wakeup(){global $flag;$flag=NULL;}public function __destruct(){global $flag;if($flag!==NULL){echo $flag;}}}
if(isset($_POST['o'])){unserialize($_POST['o']);}'''

LEVELS[12] = '''<?php class FLAG{private $f='clean_';private $l='up_';protected $a='4nd_';public $g='select_variab1es}';public $x,$y,$z;function __sleep(){return['x','y','z'];}}
class CHALLENGE extends FLAG{public $h='HelloCTF{',$e='Th3_',$l='__sleep_function_',$I='_is_',$o='called_',$c='before_',$t='serialization_',$f='t0_';public $chance;function chance(){if(isset($_GET['chance'])){return $_GET['chance'];}return 'you shuold use it';}public function __sleep(){$array_list=['h','e','l','I','o','c','t','f','f','l','a','g'];$_=array_rand($array_list);$__=array_rand($array_list);return array($array_list[$_],$array_list[$__],$this->chance());}}
$FLAG=new FLAG();echo serialize(new CHALLENGE());'''

LEVELS[13] = '''<?php class FLAG{function __toString(){include 'flag.php';return $flag;}}$obj=new FLAG();
if(isset($_POST['o'])){eval($_POST['o']);}'''

LEVELS[14] = '''<?php class FLAG{function __invoke($x){if($x=='get_flag'){include 'flag.php';echo $flag;}}}$obj=new FLAG();
if(isset($_POST['o'])){eval($_POST['o']);}'''

LEVELS[15] = '''<?php class A{public $a;function __construct($a){$this->a=$a;}}class B{public $b;function __construct($b){$this->b=$b;}}class C{public $c;function __construct($c){$this->c=$c;}}
class D{public $d;function __construct($d){$this->d=$d;}function __wakeUp(){$this->d->action();}}
class destnation{var $cmd;function __construct($cmd){$this->cmd=$cmd;}function action(){eval($this->cmd->a->b->c);}}
if(isset($_POST['o'])){unserialize($_POST['o']);}'''

LEVELS[16] = '''<?php class A{public $a;function __invoke(){include $this->a;return $flag;}}
class B{public $b;function __toString(){$f=$this->b;return $f();}}
class INIT{public $name;function __wakeUp(){echo $this->name.' is awake!';}}
if(isset($_POST['o'])){unserialize($_POST['o']);}'''

LEVELS[17] = '''<?php class A{}class B{public $a="Hello";protected $b="CTF";private $c="FLAG{TEST}";}
if(isset($_POST['o'])){$a=unserialize($_POST['o']);if($a instanceof A&&$a->helloctfcmd=="get_flag"){include 'flag.php';echo $flag;}}'''

LEVELS[18] = '''<?php class Demo{public $a="Hello";public $b="CTF";public $key='GET_FLAG";}FAKE_FLAG';}class FLAG{}
$target=$_GET['target'];$change=$_GET['change'];$serliseStringFLAG=str_replace($target,$change,serialize(new Demo()));$FLAG=unserialize($serliseStringFLAG);
if($FLAG instanceof FLAG&&$FLAG->key=='GET_FLAG'){include 'flag.php';echo $flag;}'''


def analyze_all():
    analyzer = PHPSourceAnalyzer()
    generator = PayloadGenerator()
    results = {}
    
    for num in sorted(LEVELS.keys()):
        src = LEVELS[num]
        try:
            analysis = analyzer.analyze(src, url=f"Level{num}")
            payloads = generator.generate(analysis)
            results[num] = {
                'strategy': analysis.strategy,
                'classes': [c.name for c in analysis.classes],
                'inputs': [(i.method, i.name) for i in analysis.inputs],
                'payload_count': len(payloads),
                'has_serialized': any(p.serialized_string for p in payloads),
                'has_eval': any(p.raw_code for p in payloads),
                'ok': len(payloads) > 0,
            }
        except Exception as e:
            results[num] = {'ok': False, 'error': str(e)}
    
    return results


def test_all_18_levels():
    results = analyze_all()
    for num, r in sorted(results.items()):
        status = "✓" if r['ok'] else "✗"
        info = f"strategy={r.get('strategy','?')}, payloads={r.get('payload_count',0)}"
        print(f"  [{status}] Level {num:2d}: {info}")
        if not r['ok']:
            print(f"       ERROR: {r.get('error','No payloads')}")
    ok_count = sum(1 for r in results.values() if r['ok'])
    print(f"\n  Total: {ok_count}/18 levels have payloads")
    assert ok_count >= 15, f"Only {ok_count}/18 levels generated payloads"


if __name__ == '__main__':
    test_all_18_levels()
