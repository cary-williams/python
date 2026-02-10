#!/usr/bin/env python3
# ---------------------------------------------------------------------------
# Quick repo secret hygiene scanner (not a standalone app)
#
# This script is for quickly scanning a directory (and subdirectories) to find
# potential secrets and basic secret hygiene issues when you do not need a full
# standalone secret-scanning application.
# ---------------------------------------------------------------------------

from __future__ import annotations

import argparse
import os
import re
import sys
import json
from dataclasses import dataclass, asdict
from pathlib import Path
from typing import DefaultDict, Dict, Iterable, List, Optional, Set, Tuple
from collections import defaultdict


DEFAULT_EXTENSIONS = {
    ".env", ".properties", ".yml", ".yaml", ".json", ".toml", ".ini", ".conf",
    ".py", ".js", ".ts", ".jsx", ".tsx", ".go", ".java", ".rb", ".php", ".cs",
    ".sh", ".bash", ".zsh", ".ps1", ".psm1", ".kts", ".gradle", ".xml",
    ".tf", ".tfvars", ".hcl", ".dockerfile", ".md"
}

DEFAULT_EXCLUDE_DIRS = {
    ".git", ".svn", ".hg",
    "node_modules", "vendor", "dist", "build", "target", ".venv", "venv",
    "__pycache__", ".terraform", ".idea", ".vscode"
}

BINARY_EXTENSIONS = {
    ".png", ".jpg", ".jpeg", ".gif", ".webp", ".ico",
    ".pdf", ".zip", ".gz", ".tar", ".tgz", ".7z", ".rar",
    ".exe", ".dll", ".so", ".dylib", ".bin",
    ".mp3", ".mp4", ".mov", ".avi", ".mkv",
    ".woff", ".woff2", ".ttf", ".eot"
}

DEFAULT_IGNORE_VAR_NAMES = {
    "example", "sample", "test", "testing", "dummy", "placeholder",
    "local", "localhost",
    "public", "nonsecret", "notsecret",
    "changeme",
}

SECRET_NAME_REGEX = re.compile(
    r"""(?ix)
    \b(
        api[_-]?key|
        secret|
        token|
        passwd|password|
        private[_-]?key|
        client[_-]?secret|
        access[_-]?key|
        signing[_-]?key|
        bearer|
        auth[_-]?token
    )\b
    """
)

PUBLIC_VAR_PREFIXES = ("VITE_", "NEXT_PUBLIC_", "PUBLIC_")
PUBLIC_VAR_EXACT = {
    "VITE_SUPABASE_PUBLISHABLE_KEY",
    "VITE_SUPABASE_ANON_KEY",
}

HIGH_SIGNAL_PATTERNS: List[Tuple[str, re.Pattern]] = [
    ("AWS Access Key ID", re.compile(r"\b(A3T[A-Z0-9]|AKIA|ASIA|AGPA|AIDA|AROA|ANPA|ANVA|ASCA)[A-Z0-9]{16}\b")),
    ("GitHub Token", re.compile(r"\b(ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{36,255}\b")),
    ("Slack Token", re.compile(r"\b(xox[baprs]-[A-Za-z0-9-]{10,200})\b")),
    ("Stripe Key", re.compile(r"\b(sk|rk)_(live|test)_[A-Za-z0-9]{10,200}\b")),
    ("Google API Key", re.compile(r"\bAIza[0-9A-Za-z\-_]{35}\b")),
    ("Private Key Block", re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |PGP )?PRIVATE KEY-----")),
    ("JWT (heuristic)", re.compile(r"\beyJ[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}\b")),
]

SUSPICIOUS_ASSIGNMENT = re.compile(
    r"""(?x)
    (?P<name>[A-Z0-9_]{3,}|[a-zA-Z0-9_.-]{3,})
    \s*(?:=|:)\s*
    (?P<val>
        "(?:[^"\\]|\\.){8,}" |
        '(?:[^'\\]|\\.){8,}' |
        [A-Za-z0-9/+=._-]{12,}
    )
    """,
    re.MULTILINE
)

ENV_DEFINE = re.compile(r"(?m)^\s*(?:export\s+)?(?P<name>[A-Z][A-Z0-9_]{1,})\s*=\s*.*$")
YAML_DEFINE = re.compile(r"(?m)^\s*(?P<name>[A-Z][A-Z0-9_]{1,})\s*:\s*.+$")

ENV_REF_NODE = re.compile(r"process\.env\.(?P<name>[A-Z][A-Z0-9_]{1,})")
ENV_REF_SHELL = re.compile(r"\$(?:\{)?(?P<name>[A-Z][A-Z0-9_]{1,})(?:\})?")
ENV_REF_TERRAFORM = re.compile(r"\bvar\.(?P<name>[A-Z][A-Z0-9_]{1,})\b", re.IGNORECASE)

REF_PATTERNS = [ENV_REF_NODE, ENV_REF_SHELL, ENV_REF_TERRAFORM]

DEFINE_FILE_NAMES = {
    ".env", ".env.local", ".env.example",
}
DEFINE_FILE_SUFFIXES = {".env", ".yml", ".yaml", ".tfvars", ".conf", ".ini"}


@dataclass(frozen=True)
class Finding:
    kind: str
    path: str
    line: int
    detail: str
    excerpt: str


def iter_files(root: Path, exts: Set[str], exclude_dirs: Set[str]) -> Iterable[Path]:
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in exclude_dirs]
        for fn in filenames:
            p = Path(dirpath) / fn
            if p.suffix.lower() in exts or p.name in DEFINE_FILE_NAMES:
                yield p


def safe_read_text(path: Path) -> Optional[str]:
    try:
        return path.read_text(encoding="utf-8", errors="replace")
    except Exception:
        return None


def scan_text_for_potential_secrets(text: str, path: Path) -> List[Finding]:
    findings: List[Finding] = []

    for label, pat in HIGH_SIGNAL_PATTERNS:
        for m in pat.finditer(text):
            line = text.count("\n", 0, m.start()) + 1
            excerpt = text.splitlines()[line - 1].strip()

            if label == "JWT (heuristic)":
                m_assign = re.match(r'^([A-Z][A-Z0-9_]*)\s*=', excerpt)
                if m_assign:
                    var = m_assign.group(1)
                    if var.startswith(PUBLIC_VAR_PREFIXES) or var in PUBLIC_VAR_EXACT:
                        continue

            findings.append(Finding("potential_secret", str(path), line, label, excerpt))

    for m in SUSPICIOUS_ASSIGNMENT.finditer(text):
        name = m.group("name")
        if not SECRET_NAME_REGEX.search(name):
            continue
        line = text.count("\n", 0, m.start()) + 1
        excerpt = text.splitlines()[line - 1].strip()
        findings.append(Finding("suspicious_assignment", str(path), line, f"Suspicious assignment to '{name}'", excerpt))

    return findings


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("root", nargs="?", default=".")
    parser.add_argument("--json", action="store_true", help="Output results as JSON")
    args = parser.parse_args()

    root = Path(args.root).resolve()

    findings: List[Finding] = []
    referenced: DefaultDict[str, Set[str]] = defaultdict(set)
    defined: Set[str] = set()
    files_scanned = 0

    for path in iter_files(root, DEFAULT_EXTENSIONS, DEFAULT_EXCLUDE_DIRS):
        text = safe_read_text(path)
        if not text:
            continue

        files_scanned += 1
        findings.extend(scan_text_for_potential_secrets(text, path))

        if path.name in DEFINE_FILE_NAMES or path.suffix in DEFINE_FILE_SUFFIXES:
            for m in ENV_DEFINE.finditer(text):
                defined.add(m.group("name"))

        for pat in REF_PATTERNS:
            for m in pat.finditer(text):
                name = m.group("name")
                referenced[name].add(str(path))

    unused = {v for v in defined - referenced.keys() if SECRET_NAME_REGEX.search(v)}
    missing = set(referenced.keys()) - defined

    if args.json:
        output = {
            "scan_root": str(root),
            "files_scanned": files_scanned,
            "potential_secrets": [asdict(f) for f in findings],
            "unused_secrets": sorted(unused),
            "referenced_but_not_defined": {
                k: sorted(v) for k, v in referenced.items() if k in missing
            },
        }
        print(json.dumps(output, indent=2))
    else:
        print(f"Scanned: {root}")
        print(f"Files scanned: {files_scanned}")
        print("\nPotential secrets / suspicious values:")
        print("  none found" if not findings else "")
        for f in findings:
            print(f"  [{f.kind}] {f.path}:{f.line} {f.detail}")

        print("\nUnused secrets (defined but not referenced):")
        print("  none found" if not unused else "")
        for v in sorted(unused):
            print(f"  {v}")

        print("\nReferenced but not defined:")
        print("  none found" if not missing else "")
        for k in sorted(missing):
            print(f"  {k}:")
            for p in sorted(referenced[k]):
                print(f"    - {p}")

    return 1 if findings or missing else 0


if __name__ == "__main__":
    raise SystemExit(main())
