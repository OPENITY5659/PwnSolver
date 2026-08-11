"""
Pure Python PHP serialization format encoder/decoder.
Supports: null, bool, int, float, string, array, object, references (r:N;)
Handles protected (`\0*\0`) and private (`\0ClassName\0`) property prefixes.
"""

import re
from typing import Any, Optional


# ─── Global reference tracker (for php_serialize_refs) ───

_ref_index = {}  # id(obj) -> (global_index, class_name)


def _clear_refs():
    _ref_index.clear()


def php_serialize(value: Any) -> str:
    """Serialize a Python value. No reference tracking — safe for simple values."""
    _clear_refs()
    return _serialize(value, {'next': 1})


def php_serialize_refs(value: Any) -> str:
    """Serialize with PHP reference tracking (r:N; for repeated objects).
    Call this for complex object graphs with circular/shared references."""
    _clear_refs()
    tracker = {'next': 1}
    return _serialize(value, tracker)


def _serialize(value: Any, tracker: dict) -> str:
    if value is None:
        return "N;"
    if isinstance(value, bool):
        return f"b:{1 if value else 0};"
    if isinstance(value, int):
        return f"i:{value};"
    if isinstance(value, float):
        return f"d:{value};"
    if isinstance(value, str):
        return f's:{len(value)}:"{value}";'
    if isinstance(value, (list, tuple)):
        items = enumerate(value)
        out = ""
        for k, v in items:
            out += _serialize(k, tracker) + _serialize(v, tracker)
        return f"a:{len(value)}:{{{out}}}"
    if isinstance(value, dict):
        if '__class__' in value:
            return _serialize_object(value, tracker)
        out = ""
        for k, v in value.items():
            out += _serialize(k, tracker) + _serialize(v, tracker)
        return f"a:{len(value)}:{{{out}}}"
    if hasattr(value, '__php_serialize__'):
        return value.__php_serialize__()
    raise TypeError(f"Cannot serialize type: {type(value)}")


def _serialize_object(d: dict, tracker: dict) -> str:
    """Serialize a dict as PHP object with reference tracking."""
    class_name = d['__class__']
    obj_id = id(d)

    # Check for reference
    if obj_id in _ref_index:
        return f"r:{_ref_index[obj_id][0]};"

    # Register
    idx = tracker['next']
    tracker['next'] += 1
    _ref_index[obj_id] = (idx, class_name)

    props = {k: v for k, v in d.items() if k != '__class__'}
    out = ""
    for k, v in props.items():
        out += _serialize(k, tracker) + _serialize(v, tracker)
    return f'O:{len(class_name)}:"{class_name}":{len(props)}:{{{out}}}'


def php_object(class_name: str, **properties) -> dict:
    """Convenience function: create a PHP object dict."""
    return {'__class__': class_name, **properties}


def make_protected_key(prop_name: str) -> str:
    """Protected property key: \\0*\\0name"""
    return f"\x00*\x00{prop_name}"


def make_private_key(class_name: str, prop_name: str) -> str:
    """Private property key: \\0ClassName\\0name"""
    return f"\x00{class_name}\x00{prop_name}"


# ─── Unserialize ───

def php_unserialize(data: str) -> Any:
    """Unserialize a PHP serialized string."""
    return _unserialize_value(data.strip(), 0)[0]


def _unserialize_value(data: str, pos: int):
    if pos >= len(data):
        raise ValueError("Unexpected end")
    ch = data[pos]
    if data[pos:pos+2] == 'N;':
        return None, pos + 2
    if ch == 'b':
        m = re.match(r'b:([01]);', data[pos:])
        if m: return bool(int(m.group(1))), pos + m.end()
    if ch == 'i':
        m = re.match(r'i:(-?\d+);', data[pos:])
        if m: return int(m.group(1)), pos + m.end()
    if ch == 'd':
        m = re.match(r'd:(-?[\d.]+(?:[eE][+-]?\d+)?);', data[pos:])
        if m: return float(m.group(1)), pos + m.end()
    if ch == 's':
        m = re.match(r's:(\d+):"', data[pos:])
        if m:
            L = int(m.group(1))
            s = pos + m.end()
            if s + L + 2 <= len(data) and data[s+L:s+L+2] == '";':
                return data[s:s+L], s + L + 2
    if ch == 'r':
        m = re.match(r'r:(\d+);', data[pos:])
        if m: return {'__ref__': int(m.group(1))}, pos + m.end()
    if ch == 'a':
        m = re.match(r'a:(\d+):\{', data[pos:])
        if m:
            cnt = int(m.group(1))
            pos = pos + m.end()
            result = {}
            for _ in range(cnt):
                k, pos = _unserialize_value(data, pos)
                v, pos = _unserialize_value(data, pos)
                result[k] = v
            if pos < len(data) and data[pos] == '}':
                return result, pos + 1
    if ch == 'O':
        m = re.match(r'O:(\d+):"([^"]*)":(\d+):\{', data[pos:])
        if m:
            cn = m.group(2)
            pc = int(m.group(3))
            pos = pos + m.end()
            props = {'__class__': cn}
            for _ in range(pc):
                k, pos = _unserialize_value(data, pos)
                v, pos = _unserialize_value(data, pos)
                props[k] = v
            if pos < len(data) and data[pos] == '}':
                return props, pos + 1
    raise ValueError(f"Parse error at pos {pos}: {data[pos:pos+30]!r}")


# ─── Legacy class ───

class PHPObject:
    def __init__(self, class_name: str, **properties):
        self.class_name = class_name
        self.properties = properties
    def __php_serialize__(self) -> str:
        return php_serialize({'__class__': self.class_name, **self.properties})
    def __repr__(self):
        return f"PHPObject({self.class_name}, {self.properties})"
