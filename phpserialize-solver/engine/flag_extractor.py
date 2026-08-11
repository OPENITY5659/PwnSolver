"""
Flag extractor — finds CTF flags in HTTP responses using pattern matching.
"""

import re
from typing import Optional


# Common CTF flag patterns
FLAG_PATTERNS = [
    # HelloCTF format
    re.compile(r'HelloCTF\{[^}]+\}', re.IGNORECASE),
    # Standard flag format
    re.compile(r'flag\{[^}]+\}', re.IGNORECASE),
    # Uppercase FLAG format
    re.compile(r'FLAG\{[^}]+\}', re.IGNORECASE),
    # CTF format
    re.compile(r'CTF\{[^}]+\}', re.IGNORECASE),
    # NSSCTF format
    re.compile(r'NSSCTF\{[^}]+\}', re.IGNORECASE),
    # Generic {xxx} after flag keyword
    re.compile(r'(?:flag|FLAG)\s*[:=]\s*["\']([^"\']+)["\']'),
    # Flag in quotes after "flag"
    re.compile(r'["\']([A-Za-z0-9_]+\{[^}]+\})["\']'),
    # Any curly-brace pattern that looks like a flag
    re.compile(r'([A-Z][A-Za-z0-9_]*\{[A-Za-z0-9_!@#$%^&*()\-+=\[\]|\\:;<>,.?/~` ]+\})'),
]


def extract_flags(text: str) -> list[str]:
    """Extract all flag-like strings from text."""
    if not text:
        return []

    found = set()
    for pattern in FLAG_PATTERNS:
        matches = pattern.findall(text)
        for match in matches:
            if isinstance(match, tuple):
                match = match[0] if match else ""
            match = match.strip()
            if len(match) >= 5 and len(match) <= 200:
                found.add(match)

    return sorted(found, key=len, reverse=True)


def extract_first_flag(text: str) -> Optional[str]:
    """Extract the first (most likely) flag from text."""
    flags = extract_flags(text)
    return flags[0] if flags else None


def is_likely_flag(text: str) -> bool:
    """Check if a string looks like a CTF flag."""
    if not text:
        return False
    return bool(re.match(r'^[A-Za-z0-9_]+\{[A-Za-z0-9_!@#$%^&*()\-+=\[\]|\\:;<>,.?/~` ]+\}$', text.strip()))


def extract_source_comment_flag(source: str) -> Optional[str]:
    """Try to extract flag from PHP source code comments or variable assignments."""
    patterns = [
        r'\$flag\s*=\s*["\']([^"\']+)["\']',
        r"\\$flag\s*=\s*'([^']+)'",
        r'flag\s*=\s*["\']([^"\']+)["\']',
        r'//\s*(?:flag|Flag|FLAG)\s*[:=]\s*["\']?([A-Za-z0-9_{}!@#$%^&*()\-+=\[\]|\\:;<>,.?/~` ]+)',
        r'/\*.*?(?:flag|Flag|FLAG).*?["\']([A-Za-z0-9_{}!@#$%^&*()\-+=\[\]|\\:;<>,.?/~` ]+)["\'].*?\*/',
    ]

    for pattern in patterns:
        match = re.search(pattern, source, re.DOTALL | re.IGNORECASE)
        if match:
            candidate = match.group(1).strip()
            if is_likely_flag(candidate) or 'flag' in candidate.lower():
                return candidate

    return None
