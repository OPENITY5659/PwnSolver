"""Verify GUI module is importable and functional."""
import sys
sys.path.insert(0, '.')

def test_gui_import():
    from phpuser_gui import PHPUnserGUI
    assert PHPUnserGUI is not None
    assert PHPUnserGUI.TITLE == "PHPUnser — PHP Deserialization Auto-Exploitation GUI"

def test_gui_with_source():
    """Simulate what the GUI does: analyze a sample and generate payloads."""
    from engine.analyzer import PHPSourceAnalyzer
    from engine.payload import PayloadGenerator

    source = '''<?php
class FLAG { public $cmd = "echo test;"; function __destruct() { system($this->cmd); } }
if(isset($_GET['data'])) { unserialize($_GET['data']); }
'''
    a = PHPSourceAnalyzer()
    r = a.analyze(source)
    g = PayloadGenerator()
    ps = g.generate(r)
    assert len(ps) > 0
    assert any(p.serialized_string for p in ps)

if __name__ == '__main__':
    import pytest; sys.exit(pytest.main([__file__, '-v']))
