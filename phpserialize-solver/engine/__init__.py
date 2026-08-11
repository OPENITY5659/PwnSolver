"""
PHPSerialize Auto-Solver — Engine package.
Automatically analyzes and exploits PHP deserialization CTF challenges.
"""

from .serializer import php_serialize, php_serialize_refs, php_unserialize, php_object, PHPObject
from .analyzer import PHPSourceAnalyzer, AnalysisResult
from .payload import PayloadGenerator, Payload
from .http_client import HTTPClient, HTTPResponse
from .flag_extractor import extract_flags, extract_first_flag

__all__ = [
    'php_serialize', 'php_serialize_refs',
    'php_unserialize', 'php_object', 'PHPObject',
    'PHPSourceAnalyzer',
    'AnalysisResult',
    'PayloadGenerator',
    'Payload',
    'HTTPClient',
    'HTTPResponse',
    'extract_flags',
    'extract_first_flag',
]
