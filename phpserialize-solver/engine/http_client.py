"""
HTTP Client for interacting with PHP deserialization CTF targets.
Handles session management, payload delivery, and response parsing.
"""

import re
import time
from typing import Optional
from dataclasses import dataclass, field

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry


@dataclass
class HTTPResponse:
    status_code: int
    text: str
    headers: dict
    url: str
    elapsed: float


class HTTPClient:
    """HTTP client with session support and retry logic."""

    DEFAULT_TIMEOUT = 15
    DEFAULT_RETRIES = 2
    USER_AGENT = "PHPSerialize-Solver/1.0 (CTF Auto-Exploitation Tool)"

    def __init__(self, base_url: str = "", timeout: int = DEFAULT_TIMEOUT):
        self.base_url = base_url.rstrip('/') if base_url else ""
        self.timeout = timeout
        self.session = self._create_session()
        self.last_response: Optional[HTTPResponse] = None

    def _create_session(self) -> requests.Session:
        """Create a requests session with retry logic."""
        session = requests.Session()
        session.headers.update({
            'User-Agent': self.USER_AGENT,
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
        })

        retry_strategy = Retry(
            total=self.DEFAULT_RETRIES,
            backoff_factor=0.5,
            status_forcelist=[429, 500, 502, 503, 504],
        )
        adapter = HTTPAdapter(max_retries=retry_strategy)
        session.mount("http://", adapter)
        session.mount("https://", adapter)

        return session

    def _resolve_url(self, url: str) -> str:
        """Resolve a URL relative to base_url."""
        if url.startswith('http://') or url.startswith('https://'):
            return url
        if self.base_url:
            return f"{self.base_url}/{url.lstrip('/')}"
        return url

    def get(self, url: str, params: dict = None, **kwargs) -> HTTPResponse:
        """Send a GET request."""
        full_url = self._resolve_url(url)
        timeout = kwargs.pop('timeout', self.timeout)

        try:
            resp = self.session.get(
                full_url, params=params, timeout=timeout, **kwargs
            )
            return self._build_response(resp)
        except requests.RequestException as e:
            return HTTPResponse(
                status_code=0,
                text=str(e),
                headers={},
                url=full_url,
                elapsed=0,
            )

    def post(self, url: str, data: dict = None, **kwargs) -> HTTPResponse:
        """Send a POST request with form-encoded data."""
        full_url = self._resolve_url(url)
        timeout = kwargs.pop('timeout', self.timeout)

        try:
            resp = self.session.post(
                full_url, data=data, timeout=timeout, **kwargs
            )
            return self._build_response(resp)
        except requests.RequestException as e:
            return HTTPResponse(
                status_code=0,
                text=str(e),
                headers={},
                url=full_url,
                elapsed=0,
            )

    def fetch_source(self, url: str) -> str:
        """Fetch a page and try to extract PHP source code from it."""
        resp = self.get(url)
        self.last_response = resp

        if resp.status_code == 0:
            return ""

        text = resp.text

        # Try to extract source from highlight_file output
        source = self._extract_source_from_html(text)
        if source:
            return source

        # If the page IS raw PHP source (text/plain or no HTML)
        if 'text/plain' in str(resp.headers.get('content-type', '')):
            return text

        # Try to get raw source by appending ?source or fetching the file directly
        raw_url = url
        if not url.endswith('.php.source'):
            # Some servers show source with ?source parameter
            source_resp = self.get(f"{url}?source")
            if source_resp.status_code == 200 and '<?php' in source_resp.text:
                return self._extract_source_from_html(source_resp.text)

        return text

    def _extract_source_from_html(self, html_text: str) -> str:
        """Extract PHP source code from HTML (highlight_file output)."""
        # Look for <code> blocks
        code_blocks = re.findall(
            r'<code[^>]*>(.*?)</code>',
            html_text, re.DOTALL | re.IGNORECASE
        )
        if code_blocks:
            combined = '\n'.join(code_blocks)
            if '<?php' in combined or 'class ' in combined or 'function ' in combined:
                return combined

        # Look for <pre> blocks with PHP code
        pre_blocks = re.findall(
            r'<pre[^>]*>(.*?)</pre>',
            html_text, re.DOTALL | re.IGNORECASE
        )
        for block in pre_blocks:
            if '<?php' in block or 'class ' in block:
                return block

        # Look for PHP tags in the raw HTML
        php_match = re.search(
            r'(<\?php.*?\?>)',
            html_text, re.DOTALL
        )
        if php_match:
            return php_match.group(1)

        # If the entire page looks like PHP source
        if html_text.strip().startswith('<?php'):
            return html_text

        return ""

    def _build_response(self, resp: requests.Response) -> HTTPResponse:
        """Build an HTTPResponse from a requests.Response."""
        return HTTPResponse(
            status_code=resp.status_code,
            text=resp.text,
            headers=dict(resp.headers),
            url=resp.url,
            elapsed=resp.elapsed.total_seconds(),
        )

    def test_connectivity(self, url: str = "") -> bool:
        """Test if the target is reachable."""
        try:
            target = url or self.base_url
            resp = self.get(target)
            return resp.status_code > 0
        except Exception:
            return False

    def close(self):
        """Close the HTTP session."""
        self.session.close()
