# reverse-skill Deep Recon (run via python3)
"""
深度侦察模块
============

按 reverse-skill 的 radare2 / reverse-engineering / competition-reverse-pwn
工作流，对目标二进制做结构化 triage，并落盘 Evidence。

设计约束：
- 不依赖 pwntools，pwntools 不可用时仍可运行
- rabin2 / readelf / objdump / strings 均通过 subprocess 调用，缺失时自动降级
- 输出为 JSON 兼容 dict，可被 PwnSolver 和 reverse_skill.PlaybookBuilder 直接消费
"""

from __future__ import annotations

import hashlib
import json
import math
import os
import platform
import re
import shutil
import subprocess
import time
from collections import Counter
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Tuple


def _run(args: List[str], timeout: int = 20, cwd: Optional[str] = None) -> Tuple[bool, str, str]:
    """运行命令，返回 (成功, stdout, stderr)。永不抛异常。"""
    try:
        r = subprocess.run(
            args,
            capture_output=True,
            text=True,
            timeout=timeout,
            cwd=cwd,
            errors="replace",
        )
        return True, r.stdout, r.stderr
    except FileNotFoundError:
        return False, "", f"{args[0]}: not found"
    except subprocess.TimeoutExpired:
        return False, "", f"{args[0]}: timeout after {timeout}s"
    except Exception as exc:
        return False, "", f"{args[0]}: {exc}"


def _parse_json(text: str) -> Any:
    """rabin2 -j 有时会在 JSON 前打印 WARN 行，这里做容错解析。"""
    text = text.strip()
    if not text:
        return None
    starts = [i for i, ch in enumerate(text) if ch in "[{"]
    for start in starts:
        for end in range(len(text), start, -1):
            if end - start < 2:
                continue
            try:
                return json.loads(text[start:end])
            except json.JSONDecodeError:
                continue
    return None


def _entropy(data: bytes) -> float:
    if not data:
        return 0.0
    counter = Counter(data)
    length = len(data)
    return -sum((c / length) * math.log2(c / length) for c in counter.values())


class DeepRecon:
    """Binary triage + packer/language/anti-analysis detection."""

    def __init__(self, binary_path: str, verbose: bool = False,
                 workdir: Optional[str] = None, run_r2_analysis: bool = False):
        self.binary_path = os.path.abspath(binary_path)
        self.binary = Path(self.binary_path)
        self.verbose = verbose
        self.workdir = workdir
        self.run_r2_analysis = run_r2_analysis
        self._cache: Dict[str, Any] = {}

        if not self.binary.exists():
            raise FileNotFoundError(f"Binary not found: {self.binary_path}")

    def log(self, msg: str) -> None:
        if self.verbose:
            print(f"  [recon] {msg}", flush=True)

    # ------------------------------------------------------------------
    def run(self) -> Dict[str, Any]:
        """执行完整侦察。"""
        started = time.time()
        self.log("文件分诊 + hash + entropy")
        hashes = self.hashes()
        file_type = self.file_type()
        sample = self._read_prefix(1024 * 1024)
        entropy = _entropy(sample)

        self.log("rabin2 结构信息")
        r2_info = self.rabin2_info()
        sections = self.rabin2_sections()
        imports = self.rabin2_imports()
        exports = self.rabin2_exports()
        strings = self.strings_interesting()

        self.log("packer / language / anti-analysis")
        packed = self.detect_packer(r2_info, sections, imports, entropy)
        language = self.detect_language(r2_info, sections, strings)
        anti = self.detect_anti_analysis(imports, strings)

        self.log("工具链")
        tooling = self.toolchain()

        self.log("r2 函数级分析")
        r2_functions: Dict[str, Any] = {}
        tool_status = tooling.get("status") or {}
        if self.run_r2_analysis and tool_status.get("r2", {}).get("ok"):
            r2_functions = self.r2_function_analysis()

        result = {
            "binary_path": self.binary_path,
            "sha256": hashes["sha256"],
            "sha1": hashes["sha1"],
            "md5": hashes["md5"],
            "size": self.binary.stat().st_size,
            "file_type": file_type,
            "magic": sample[:16].hex(" "),
            "entropy": round(entropy, 4),
            "info": r2_info,
            "sections": sections,
            "imports": imports,
            "exports": exports,
            "interesting_strings": strings,
            "packed": packed,
            "language": language,
            "anti_analysis": anti,
            "tooling": tooling,
            "r2_functions": r2_functions,
            "elapsed_seconds": round(time.time() - started, 3),
            "producer": "PwnSolver DeepRecon (reverse-skill: radare2 + reverse-engineering + competition-reverse-pwn)",
        }
        self._cache = result
        return result

    # ------------------------------------------------------------------
    # 基础
    # ------------------------------------------------------------------
    def _read_prefix(self, size: int) -> bytes:
        with open(self.binary_path, "rb") as fh:
            return fh.read(size)

    def hashes(self) -> Dict[str, str]:
        h256, h1, hmd5 = hashlib.sha256(), hashlib.sha1(), hashlib.md5()
        with open(self.binary_path, "rb") as fh:
            for chunk in iter(lambda: fh.read(1024 * 1024), b""):
                h256.update(chunk)
                h1.update(chunk)
                hmd5.update(chunk)
        return {"sha256": h256.hexdigest(), "sha1": h1.hexdigest(), "md5": hmd5.hexdigest()}

    def file_type(self) -> str:
        ok, out, err = _run(["file", "-b", self.binary_path], timeout=10)
        if ok and out.strip():
            return out.strip()
        magic = self._read_prefix(16)
        if magic.startswith(b"\x7fELF"):
            return "ELF binary"
        if magic.startswith(b"MZ"):
            return "PE binary"
        if magic.startswith(b"\xcf\xfa\xed\xfe"):
            return "Mach-O binary"
        return "unknown (file unavailable)"

    def rabin2_info(self) -> Dict[str, Any]:
        if "rabin2_info" in self._cache:
            return self._cache["rabin2_info"]
        ok, out, err = _run(["rabin2", "-I", "-j", self.binary_path], timeout=20)
        data = _parse_json(out) if ok else None
        if isinstance(data, dict):
            return data.get("info", data)
        # 降级: readelf -h 文本摘要
        ok, out, _ = _run(["readelf", "-h", self.binary_path], timeout=10)
        if ok:
            return {"_fallback": "readelf -h", "raw": out[:2000]}
        return {"_error": "rabin2/readelf unavailable"}

    def rabin2_sections(self) -> List[Dict[str, Any]]:
        ok, out, _ = _run(["rabin2", "-S", "-j", self.binary_path], timeout=20)
        data = _parse_json(out) if ok else None
        if isinstance(data, list):
            return data
        if isinstance(data, dict) and isinstance(data.get("sections"), list):
            return data["sections"]
        return []

    def rabin2_imports(self) -> List[Dict[str, Any]]:
        ok, out, _ = _run(["rabin2", "-i", "-j", self.binary_path], timeout=20)
        data = _parse_json(out) if ok else None
        if isinstance(data, dict) and isinstance(data.get("imports"), list):
            return data["imports"]
        if isinstance(data, list):
            return data
        return []

    def rabin2_exports(self) -> List[Dict[str, Any]]:
        ok, out, _ = _run(["rabin2", "-E", "-j", self.binary_path], timeout=20)
        data = _parse_json(out) if ok else None
        if isinstance(data, dict) and isinstance(data.get("exports"), list):
            return data["exports"]
        if isinstance(data, list):
            return data
        return []

    def strings_interesting(self, max_lines: int = 80) -> List[str]:
        ok, out, _ = _run(["strings", "-n", "5", self.binary_path], timeout=30)
        if not ok:
            return []
        keywords = (
            "/bin/sh", "flag", "ctf", "system", "execve", "shell", "win",
            "password", "admin", "secret", "ptrace", "LD_PRELOAD", "seccomp",
            "PR_SET", "open", "read", "write", "mprotect", "/proc/self",
            "gopclntab", "go.buildid", "rust", "panic", "puts", "printf",
            "pb-c", "protobuf", "pack_to_buffer",
        )
        found: List[str] = []
        for line in out.splitlines():
            low = line.lower()
            if any(k.lower() in low for k in keywords):
                found.append(line.strip())
                if len(found) >= max_lines:
                    break
        return found

    # ------------------------------------------------------------------
    # 检测器
    # ------------------------------------------------------------------
    def detect_packer(self, info: Dict[str, Any], sections: List[Dict[str, Any]],
                      imports: List[Dict[str, Any]], entropy: float) -> Dict[str, Any]:
        result: Dict[str, Any] = {
            "packed": False,
            "packer": None,
            "confidence": 0.0,
            "entropy": entropy,
            "evidence": [],
        }
        prefix = self._read_prefix(4 * 1024 * 1024)

        markers = {
            b"UPX!": "UPX",
            b"MPRESS": "MPRESS",
            b"Mpress": "MPRESS",
            b"ASPack": "ASPack",
            b"PECompact": "PECompact",
            b"NsPacK": "NsPack",
        }
        for marker, name in markers.items():
            if marker in prefix:
                result.update({"packed": True, "packer": name, "confidence": 0.98})
                result["evidence"].append(f"packer marker found: {marker!r}")
                break

        sec_names = [str(s.get("name", "")).lower() for s in sections]
        if "upx0" in sec_names or "upx1" in sec_names:
            result.update({"packed": True, "packer": result.get("packer") or "UPX", "confidence": max(result["confidence"], 0.9)})
            result["evidence"].append("UPX0/UPX1 sections found")

        import_names = {str(i.get("name", "")).lower() for i in imports}
        if entropy > 7.5 and len(import_names) <= 3 and prefix.startswith(b"\x7fELF"):
            result["packed"] = True
            result["packer"] = result.get("packer") or "custom/unknown"
            result["confidence"] = max(result["confidence"], 0.55)
            result["evidence"].append(f"high entropy ({entropy:.2f}) + very few imports ({len(import_names)})")

        # 自定义 ELF 壳常见特征: RWX PT_LOAD 且 entry 不在首个 RX 段
        if isinstance(info, dict) and str(info.get("bintype", "")).lower() in ("elf", "elf64", "elf32"):
            if info.get("static") and entropy > 7.4:
                result["packed"] = True
                result["packer"] = result.get("packer") or "suspected static/custom packer"
                result["confidence"] = max(result["confidence"], 0.5)
                result["evidence"].append("static ELF with high-entropy payload")
        return result

    def detect_language(self, info: Dict[str, Any], sections: List[Dict[str, Any]],
                        strings: List[str]) -> Dict[str, Any]:
        sec_names = {str(s.get("name", "")).lower() for s in sections}
        blob = " ".join(strings).lower()
        result: Dict[str, Any] = {
            "c": True,
            "cpp": False,
            "go": False,
            "rust": False,
            "protobuf_c": False,
            "static": bool(info.get("static")) if isinstance(info, dict) else False,
            "stripped": bool(info.get("stripped")) if isinstance(info, dict) else False,
            "evidence": [],
        }

        cpp_marks = ("__cxa_throw", "__gxx_personality", "_ztv", "_zst", "std::")
        if any(m.lower() in blob for m in cpp_marks):
            result["cpp"] = True
            result["evidence"].append("C++ runtime/name-mangling markers")
        if "gopclntab" in sec_names or ".go.buildinfo" in sec_names:
            result["go"] = True
            result["evidence"].append("Go pclntab/buildinfo section")
        if any(m.lower() in blob for m in ("go build id:", "go.buildid", "runtime.main", "gopclntab")):
            result["go"] = True
            result["evidence"].append("Go runtime string markers")
        if any(m.lower() in blob for m in ("rust_eh_personality", "panicked at", "rust_begin_unwind", "/rustc/")):
            result["rust"] = True
            result["evidence"].append("Rust runtime/panic markers")
        if any(m.lower() in blob for m in ("pb-c", "protobuf_c_message", "pack_to_buffer", "message->base.descriptor")):
            result["protobuf_c"] = True
            result["evidence"].append("protobuf-c generated pack/unpack routines")
        if b'\x28\xaa\xee\xf9' in self._read_prefix(1024 * 1024):
            result["protobuf_c"] = True
            result["evidence"].append("ProtobufCMessageDescriptor magic 0x28AAEEF9")
        if not result["evidence"]:
            result["evidence"].append("no strong language markers; assume native C/C-like")
        return result

    def detect_anti_analysis(self, imports: List[Dict[str, Any]],
                             strings: List[str]) -> Dict[str, Any]:
        import_names = {str(i.get("name", "")).lower() for i in imports}
        string_blob = "\n".join(strings).lower()

        def has_import(*needles: str) -> bool:
            return any(n in import_names for n in needles)

        ptrace_import = has_import("ptrace", "ptrace@plt")
        prctl_import = has_import("prctl", "__prctl")
        seccomp_import = has_import("seccomp_init", "seccomp_load", "seccomp_rule_add")
        proc_self_mem = "/proc/self/mem" in string_blob
        tracerpid = "tracerpid" in string_blob
        ld_preload = "ld_preload" in string_blob
        alarm_import = has_import("alarm", "setitimer")

        anti_debug = bool(ptrace_import or tracerpid or proc_self_mem or ld_preload)
        result = {
            "anti_debug": anti_debug,
            "anti_analysis": bool(anti_debug or prctl_import or alarm_import),
            "ptrace": ptrace_import or tracerpid,
            "proc_self_mem": proc_self_mem,
            "ld_preload_detect": ld_preload,
            "prctl": prctl_import,
            "seccomp": seccomp_import,
            "alarm": alarm_import,
            "evidence": [],
        }
        if ptrace_import:
            result["evidence"].append("ptrace import")
        if tracerpid:
            result["evidence"].append("TracerPid scan")
        if proc_self_mem:
            result["evidence"].append("reads /proc/self/mem")
        if ld_preload:
            result["evidence"].append("LD_PRELOAD detection")
        if prctl_import:
            result["evidence"].append("prctl import (possibly seccomp/dumpable hardening)")
        if seccomp_import:
            result["evidence"].append("libseccomp import: exploit must obey syscall filter")
        if not result["evidence"]:
            result["evidence"].append("no obvious anti-analysis marker")
        return result

    def toolchain(self) -> Dict[str, Any]:
        from reverse_skill import ToolProbe
        tp = ToolProbe()
        status = tp.check()
        result: Dict[str, Any] = {
            "status": status,
            "missing": tp.missing(),
            "host": {
                "system": platform.system(),
                "machine": platform.machine(),
            },
            "need_x86_container": tp.x86_container_needed(self.rabin2_info()),
        }
        return result

    def r2_function_analysis(self, timeout: int = 60) -> Dict[str, Any]:
        """可选: r2 -2 -c 'aaa; afl~?' 获取函数数；只对大样本节流。"""
        if self.binary.stat().st_size > 50 * 1024 * 1024:
            return {"skipped": "binary > 50MB"}
        commands = "aaa; aflc; afl~main,win,system,read,gets,scanf,printf,free,malloc"
        ok, out, _ = _run(
            ["r2", "-2", "-q", "-e", "bin.cache=true", "-c", commands, self.binary_path],
            timeout=timeout,
        )
        if not ok:
            return {"error": _ or "r2 failed"}
        lines = [ln.strip() for ln in out.splitlines() if ln.strip()]
        return {
            "raw_head": lines[:40],
            "function_count": lines[0] if lines and lines[0].isdigit() else None,
        }

    # ------------------------------------------------------------------
    # Evidence 输出
    # ------------------------------------------------------------------
    def evidence_dir(self) -> Path:
        if self.workdir:
            base = Path(self.workdir).expanduser().resolve()
        else:
            base = self.binary.parent
            # /bin、/usr/bin 等系统路径不可写时回退到当前目录
            if not os.access(base, os.W_OK):
                base = Path.cwd()
        return base / "pwnsolver_evidence"

    def write_evidence(self, result: Optional[Dict[str, Any]] = None) -> Dict[str, str]:
        result = result or self._cache or self.run()
        evdir = self.evidence_dir()
        evdir.mkdir(parents=True, exist_ok=True)
        stem = self.binary.stem or "binary"

        json_path = evdir / f"{stem}.recon.json"
        json_path.write_text(json.dumps(result, ensure_ascii=False, indent=2), encoding="utf-8")

        md_path = evdir / f"{stem}.recon.md"
        md_path.write_text(self._render_markdown(result), encoding="utf-8")

        return {
            "evidence_dir": str(evdir),
            "json": str(json_path),
            "markdown": str(md_path),
        }

    def _render_markdown(self, r: Dict[str, Any]) -> str:
        lines = [
            f"# Recon Evidence — {Path(r['binary_path']).name}",
            "",
            f"- sha256: `{r['sha256']}`",
            f"- size: {r['size']} bytes",
            f"- file: {r['file_type']}",
            f"- entropy: {r['entropy']}",
            "",
            "## Packer",
            "",
            json.dumps(r.get("packed"), ensure_ascii=False, indent=2),
            "",
            "## Language",
            "",
            json.dumps(r.get("language"), ensure_ascii=False, indent=2),
            "",
            "## Anti-Analysis / Seccomp",
            "",
            json.dumps(r.get("anti_analysis"), ensure_ascii=False, indent=2),
            "",
            "## Imports (first 60)",
            "",
        ]
        for imp in r.get("imports", [])[:60]:
            name = imp.get("name") or imp.get("bind") or "?"
            lines.append(f"- `{name}`")
        lines += ["", "## Interesting strings (first 60)", ""]
        for s in r.get("interesting_strings", [])[:60]:
            lines.append(f"- `{s}`")
        lines += ["", "## Evidence provenance", "",
                  "- Commands: file, sha256sum, rabin2 -I/-S/-i/-E/-z, strings",
                  "- Skill routing: reverse-skill `radare2` + `reverse-engineering` + `competition-reverse-pwn`",
                  "- Scope contract: reverse_skill/skills/ops/scope-contract.md"]
        return "\n".join(lines)


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="PwnSolver Deep Recon")
    parser.add_argument("binary")
    parser.add_argument("--evidence-dir", default=None)
    parser.add_argument("--r2-analysis", action="store_true", help="运行 r2 aaa 函数级分析")
    parser.add_argument("-q", "--quiet", action="store_true")
    args = parser.parse_args()

    recon = DeepRecon(args.binary, verbose=not args.quiet,
                      workdir=args.evidence_dir, run_r2_analysis=args.r2_analysis)
    result = recon.run()
    print(json.dumps(result, ensure_ascii=False, indent=2))
    print("\nEvidence files:")
    print(json.dumps(recon.write_evidence(result), ensure_ascii=False, indent=2))
