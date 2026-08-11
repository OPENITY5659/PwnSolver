"""
PHP Source Code Analyzer for CTF PHP deserialization challenges.
Extracts: classes, properties (with visibility), magic methods, sinks, inputs, and flag conditions.
"""

import re
import html
from typing import Optional
from dataclasses import dataclass, field


@dataclass
class Property:
    name: str
    visibility: str  # public, protected, private, var
    default_value: Optional[str] = None
    class_name: str = ""  # needed for private property key generation


@dataclass
class Method:
    name: str
    visibility: str
    body: str
    is_magic: bool = False


@dataclass
class PHPClass:
    name: str
    parent: Optional[str] = None
    properties: list[Property] = field(default_factory=list)
    methods: list[Method] = field(default_factory=list)


@dataclass
class Sink:
    type: str  # eval, unserialize, include, system, exec, shell_exec, passthru, assert
    parameter: str  # the input variable used
    context: str  # surrounding code context
    class_name: Optional[str] = None
    method_name: Optional[str] = None


@dataclass
class InputParam:
    name: str
    method: str  # POST, GET, REQUEST, COOKIE
    used_in_sink: bool = False
    used_in_unserialize: bool = False
    used_in_eval: bool = False


@dataclass
class FlagCondition:
    condition_type: str
    condition_code: str
    flag_pattern: str
    requires: list[str] = field(default_factory=list)
    target_property: Optional[str] = None
    target_value: Optional[str] = None


@dataclass
class AnalysisResult:
    url: str
    classes: list[PHPClass] = field(default_factory=list)
    sinks: list[Sink] = field(default_factory=list)
    inputs: list[InputParam] = field(default_factory=list)
    flag_conditions: list[FlagCondition] = field(default_factory=list)
    raw_source: str = ""
    strategy: str = ""


class PHPSourceAnalyzer:
    """Analyze PHP source code for deserialization vulnerabilities."""

    def analyze(self, source: str, url: str = "") -> AnalysisResult:
        """Analyze PHP source code and return structured results."""
        result = AnalysisResult(url=url, raw_source=source)
        source = self._clean_source(source)
        result.classes = self._extract_classes(source)
        result.sinks = self._extract_sinks(source)
        result.inputs = self._extract_inputs(source)
        self._link_inputs_to_sinks(result)
        result.flag_conditions = self._extract_flag_conditions(source, result)
        result.strategy = self._detect_strategy(source, result)
        return result

    def _clean_source(self, source: str) -> str:
        """Clean HTML-encoded PHP source to plain PHP."""
        source = html.unescape(source)
        code_match = re.search(
            r'<code[^>]*>(.*?)</code>',
            source, re.DOTALL | re.IGNORECASE
        )
        if code_match and ('<?php' in code_match.group(1) or 'class ' in code_match.group(1)):
            source = code_match.group(1)
        known_tags = [
            'span', 'code', 'pre', 'div', 'br', 'font', 'b', 'i', 'strong',
            'em', 'a', 'p', 'h1', 'h2', 'h3', 'h4', 'h5', 'h6',
            'table', 'tr', 'td', 'th', 'ul', 'ol', 'li',
            'html', 'head', 'body', 'title', 'meta', 'link', 'script', 'style',
        ]
        for tag in known_tags:
            source = re.sub(rf'<\s*{tag}[^>]*>', '', source, flags=re.IGNORECASE)
            source = re.sub(rf'<\s*/\s*{tag}\s*>', '', source, flags=re.IGNORECASE)
        source = re.sub(r'<\s*br\s*/?\s*>', '', source, flags=re.IGNORECASE)
        source = re.sub(r'<\s*hr\s*/?\s*>', '', source, flags=re.IGNORECASE)
        source = source.replace('&nbsp;', ' ').replace('&#160;', ' ')
        source = source.replace('&#039;', "'").replace('&quot;', '"')
        return source

    def _extract_classes(self, source: str) -> list[PHPClass]:
        """Extract all PHP class definitions (including final/abstract/implements)."""
        classes = []
        for class_match in re.finditer(
            r'(?:(?:final|abstract)\s+)?class\s+(\w+)(?:\s+extends\s+(\w+))?(?:\s+implements\s+[^{]+)?\s*\{',
            source
        ):
            class_name = class_match.group(1)
            parent = class_match.group(2)
            cls = PHPClass(name=class_name, parent=parent)
            start = class_match.end()
            body = self._extract_braced_block(source, start - 1)
            if body is None:
                continue

            # Find method boundaries to exclude their local variables from property extraction
            method_ranges = []
            for mm in re.finditer(
                r'(?:(?:public|protected|private)\s+)?function\s+(\w+)\s*\([^)]*\)\s*\{',
                body
            ):
                m_body = self._extract_braced_block(body, mm.end() - 1)
                if m_body:
                    method_ranges.append((mm.start(), mm.start() + len(m_body)))

            # Extract properties only from class-level (not inside methods)
            # REQUIRES explicit visibility keyword to avoid matching local variables
            for pm in re.finditer(
                r'(public|protected|private|var)\s+\$(\w+)\s*(?:=\s*([^;]*?))?\s*;',
                body
            ):
                ppos = pm.start()
                # Double-check: skip if inside a method body
                if any(mr[0] <= ppos < mr[1] for mr in method_ranges):
                    continue
                visibility = pm.group(1)
                if visibility == 'var':
                    visibility = 'public'
                dv = pm.group(3)
                if dv:
                    dv = dv.strip().strip('"').strip("'")
                    # Convert PHP literal booleans and null
                    if dv.lower() == 'true': dv = True
                    elif dv.lower() == 'false': dv = False
                    elif dv.lower() == 'null': dv = None
                cls.properties.append(Property(
                    name=pm.group(2), visibility=visibility,
                    default_value=dv, class_name=class_name,
                ))

            # Extract methods
            for mm in re.finditer(
                r'(?:(public|protected|private)\s+)?function\s+(\w+)\s*\(([^)]*)\)\s*\{',
                body
            ):
                vis = mm.group(1) or 'public'
                mn = mm.group(2)
                m_body = self._extract_braced_block(body, mm.end() - 1)
                if m_body is None:
                    m_body = ""
                cls.methods.append(Method(
                    name=mn.lower(), visibility=vis,
                    body=m_body, is_magic=mn.startswith('__'),
                ))
            classes.append(cls)
        return classes

    def _extract_sinks(self, source: str) -> list[Sink]:
        """Detect dangerous function calls using balanced-paren matching."""
        sinks = []
        # Balanced-paren pattern: handles one level of nesting
        BAL = r'([^()]*(?:\([^()]*\)[^()]*)*)'

        for match in re.finditer(r'eval\s*\(' + BAL + r'\)', source):
            sinks.append(Sink(type='eval', parameter=match.group(1).strip(), context=match.group(0)))

        for match in re.finditer(r'unserialize\s*\(' + BAL + r'\)', source):
            param = match.group(1).strip()
            if '$' in param or 'str_replace' in param:
                sinks.append(Sink(type='unserialize', parameter=param, context=match.group(0)))

        for match in re.finditer(
            r'(?:include|require|include_once|require_once)\s*\(?\s*(\$[^;)]+?|\'[^\']+\'|"[^"]+")\s*\)?\s*;',
            source
        ):
            sinks.append(Sink(type='include', parameter=match.group(1).strip(), context=match.group(0)))

        for match in re.finditer(r'(system|exec|shell_exec|passthru|assert)\s*\(' + BAL + r'\)', source):
            sinks.append(Sink(type=match.group(1), parameter=match.group(2).strip(), context=match.group(0)))

        return sinks

    def _extract_inputs(self, source: str) -> list[InputParam]:
        """Detect HTTP input parameters (case-insensitive superglobal matching)."""
        inputs = []
        seen = set()
        for match in re.finditer(
            r'\$_(POST|GET|REQUEST|COOKIE)\s*\[\s*["\']([^"\']+)["\']\s*\]',
            source, re.IGNORECASE
        ):
            method = match.group(1).upper()
            param_name = match.group(2)
            key = (method, param_name)
            if key not in seen:
                seen.add(key)
                inputs.append(InputParam(name=param_name, method=method))
        return inputs

    def _link_inputs_to_sinks(self, result: AnalysisResult):
        """Mark which inputs are used in sinks. Handles both single- and double-quoted keys."""
        for inp in result.inputs:
            refs = []
            q1 = f"$_POST['{inp.name}']"
            q2 = f'$_POST["{inp.name}"]'
            if inp.method == "POST":
                refs = [q1, q2]
            elif inp.method == "GET":
                refs = [f"$_GET['{inp.name}']", f'$_GET["{inp.name}"]']
            elif inp.method == "REQUEST":
                refs = [f"$_REQUEST['{inp.name}']", f'$_REQUEST["{inp.name}"]']
            elif inp.method == "COOKIE":
                refs = [f"$_COOKIE['{inp.name}']", f'$_COOKIE["{inp.name}"]']
            for sink in result.sinks:
                for ref in refs:
                    if ref in sink.parameter:
                        inp.used_in_sink = True
                        if sink.type == 'eval':
                            inp.used_in_eval = True
                        if sink.type == 'unserialize':
                            inp.used_in_unserialize = True
                        break

    def _extract_flag_conditions(self, source: str, result: AnalysisResult) -> list[FlagCondition]:
        """Extract flag output conditions."""
        conditions = []
        if re.search(r"include\s+['\"]flag\.php['\"]", source):
            conditions.append(FlagCondition(
                condition_type='include_flag_php', condition_code='include flag.php',
                flag_pattern=r'[A-Za-z0-9_{}]+', requires=['trigger_include'],
            ))
        if_match = re.search(
            r'if\s*\(([^)]+)\)\s*\{[^}]*include\s+[\'"]flag\.php[\'"]\s*;[^}]*echo\s+\$flag',
            source, re.DOTALL
        )
        if if_match:
            conditions.append(FlagCondition(
                condition_type='explicit_check', condition_code=if_match.group(1).strip(),
                flag_pattern=r'[A-Za-z0-9_{}]+',
                requires=['satisfy_condition', if_match.group(1).strip()],
            ))
        fm = re.search(r'\$flag\s*=\s*["\']([A-Za-z0-9_{}!@#$%^&*()\-+=\[\]|\\:;<>,.?/~`\s]+)["\']', source)
        if fm:
            conditions.append(FlagCondition(
                condition_type='echo_variable', condition_code=f'$flag = "{fm.group(1)}"',
                flag_pattern=re.escape(fm.group(1)), requires=['trigger_echo'],
            ))
        for cls in result.classes:
            for prop in cls.properties:
                if prop.default_value and isinstance(prop.default_value, str) and re.search(r'[Hh]ello[Cc][Tt][Ff]\{', prop.default_value):
                    conditions.append(FlagCondition(
                        condition_type='echo_variable',
                        condition_code=f'Property {cls.name}::${prop.name} = {prop.default_value}',
                        flag_pattern=re.escape(prop.default_value),
                        requires=['trigger_echo'],
                        target_property=prop.name, target_value=prop.default_value,
                    ))
        return conditions

    def _detect_strategy(self, source: str, result: AnalysisResult) -> str:
        """Auto-detect the exploitation strategy."""
        has_eval = any(s.type == 'eval' for s in result.sinks)
        has_eval_input = any(i.used_in_eval for i in result.inputs)
        has_unserialize = any(s.type == 'unserialize' for s in result.sinks)
        has_unserialize_input = any(i.used_in_unserialize for i in result.inputs)
        has_any_post = any(i.method == 'POST' for i in result.inputs)
        has_any_get = any(i.method == 'GET' for i in result.inputs)
        has_se = bool(re.search(r'(?:str_replace.*unserialize|serialize.*str_replace)', source, re.DOTALL))
        has_pop = bool(re.search(r'\$this->\w+->\w+->', source))
        has_wb = bool(re.search(r'__wakeup.*(?:NULL|unset|\$flag\s*=)', source, re.DOTALL))

        if has_se:
            return "string_escape"
        elif has_pop:
            return "pop_chain"
        elif has_wb and has_unserialize:
            return "wakeup_bypass"
        elif has_unserialize and (has_unserialize_input or has_any_post):
            mm = set()
            for cls in result.classes:
                for m in cls.methods:
                    if m.is_magic:
                        mm.add(m.name)
            if '__wakeup' in mm and '__destruct' in mm:
                return "unserialize_wakeup_destruct"
            elif '__destruct' in mm:
                return "unserialize_destruct"
            elif '__wakeup' in mm:
                return "unserialize_wakeup"
            elif '__tostring' in mm:
                return "unserialize_toString"
            elif '__invoke' in mm:
                return "unserialize_invoke"
            else:
                return "unserialize_injection"
        elif has_eval and (has_eval_input or has_any_post):
            return "eval_injection"
        elif has_eval:
            return "eval_injection"
        elif has_any_post or has_any_get:
            if re.search(r'(?:serialize|unserialize)', source):
                return "unserialize_injection"
            return "eval_injection"
        else:
            return "unknown"

    def _extract_braced_block(self, text: str, open_pos: int) -> Optional[str]:
        """Extract content between matching braces, skipping strings and comments."""
        if open_pos >= len(text) or text[open_pos] != '{':
            return None
        depth = 1
        pos = open_pos + 1
        in_string = False
        string_char = ''
        in_line = False
        in_block = False
        esc = False
        while pos < len(text) and depth > 0:
            ch = text[pos]
            ch2 = text[pos:pos+2] if pos + 1 < len(text) else ''
            if esc:
                esc = False
                pos += 1
                continue
            if in_block:
                if ch2 == '*/':
                    in_block = False
                    pos += 2
                    continue
                pos += 1
                continue
            if in_line:
                if ch == '\n':
                    in_line = False
                pos += 1
                continue
            if in_string:
                if ch == '\\':
                    esc = True
                elif ch == string_char:
                    in_string = False
                pos += 1
                continue
            if ch2 in ('//', '#'):
                in_line = True
                pos += 2
                continue
            if ch2 == '/*':
                in_block = True
                pos += 2
                continue
            if ch in ('"', "'"):
                in_string = True
                string_char = ch
            elif ch == '{':
                depth += 1
            elif ch == '}':
                depth -= 1
            pos += 1
        if depth == 0:
            return text[open_pos:pos]
        return None
