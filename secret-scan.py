#!/usr/bin/env python3
# ---------------------------------------------------------------------------
# Quick repo secret hygiene scanner 
#
# This script provides a lightweight way to scan a directory (and its
# subdirectories) for potential secrets and common secret hygiene issues when
# a full standalone scanning application is unnecessary.
#
# It can:
#   1) Detect potential secrets (high-signal patterns and suspicious assignments)
#   2) Identify unused secrets (defined but never referenced)
#   3) Flag secrets that are referenced but not defined (e.g., env vars in code)
#
# Notes:
# - Heuristic-based; not a replacement for tools like Gitleaks or TruffleHog.
# - Scans files on disk only; git history is not analyzed.
# - Paths are printed relative to the scan root by default.
#
# Args:
#   --json       Output results in JSON format
#   --full-path  Print absolute paths instead of paths relative to the scan root
# ---------------------------------------------------------------------------


from __future__ import annotations

import argparse
import json
import os
import re
import sys
from collections import defaultdict
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import DefaultDict, Dict, Iterable, List, Optional, Set, Tuple


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

# If a variable is explicitly "public" by convention, suppress JWT-only hits for it.
PUBLIC_VAR_PREFIXES = ("VITE_", "NEXT_PUBLIC_", "PUBLIC_")
PUBLIC_VAR_EXACT = {
    "VITE_SUPABASE_PUBLISHABLE_KEY",
    "VITE_SUPABASE_ANON_KEY",
}

HIGH_SIGNAL_PATTERNS: List[Tuple[str, re.Pattern]] = [
    ("AWS Access Key ID", re.compile(r"\b(A3T[A-Z0-9]|AKIA|ASIA|AGPA|AIDA|AROA|ANPA|ANVA|ASCA)[A-Z0-9]{16}\b")),
    ("AWS Secret Access Key (heuristic)", re.compile(r"(?i)\baws(.{0,20})?(secret|private|access).{0,20}[:=]\s*['\"]?[A-Za-z0-9/+=]{40}['\"]?")),
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

# Definition sources
DEFINE_FILE_NAMES = {".env", ".env.local", ".env.example"}
DEFINE_FILE_SUFFIXES = {".env", ".yml", ".yaml", ".tfvars", ".conf", ".ini"}


@dataclass(frozen=True)
class Finding:
    kind: str
    path: str
    line: int
    detail: str
    excerpt: str


def format_path(path_str: str, root: Path, full_path: bool) -> str:
    p = Path(path_str)
    if full_path:
        return str(p.resolve())
    try:
        return str(p.resolve().relative_to(root))
    except ValueError:
        return path_str


def is_probably_binary(path: Path) -> bool:
    if path.suffix.lower() in BINARY_EXTENSIONS:
        return True
    try:
        with path.open("rb") as f:
            chunk = f.read(2048)
        return b"\x00" in chunk
    except Exception:
        return True


def iter_files(root: Path, exts: Set[str], exclude_dirs: Set[str]) -> Iterable[Path]:
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in exclude_dirs]
        for fn in filenames:
            p = Path(dirpath) / fn
            if p.is_symlink():
                continue
            if p.name in DEFINE_FILE_NAMES:
                yield p
                continue
            if p.suffix.lower() in exts or p.name.endswith(".env"):
                yield p


def safe_read_text(path: Path, max_bytes: int = 2_000_000) -> Optional[str]:
    try:
        if path.stat().st_size > max_bytes:
            return None
        if is_probably_binary(path):
            return None
        return path.read_text(encoding="utf-8", errors="replace")
    except Exception:
        return None


def ignore_var(name: str, ignore_names: Set[str]) -> bool:
    low = name.lower()
    if low in ignore_names:
        return True
    if low in {"path", "home", "shell", "user", "username", "hostname", "port"}:
        return True
    return False


def scan_text_for_potential_secrets(text: str, path: Path) -> List[Finding]:
    findings: List[Finding] = []

    for label, pat in HIGH_SIGNAL_PATTERNS:
        for m in pat.finditer(text):
            line = text.count("\n", 0, m.start()) + 1
            excerpt = text.splitlines()[line - 1].strip() if line - 1 < len(text.splitlines()) else ""

            if label == "JWT (heuristic)":
                m_assign = re.match(r'^([A-Z][A-Z0-9_]*)\s*=', excerpt)
                if m_assign:
                    var = m_assign.group(1)
                    if var.startswith(PUBLIC_VAR_PREFIXES) or var in PUBLIC_VAR_EXACT:
                        continue

            findings.append(Finding("potential_secret", str(path), line, label, excerpt[:240]))

    for m in SUSPICIOUS_ASSIGNMENT.finditer(text):
        name = m.group("name")
        val = m.group("val")

        if not SECRET_NAME_REGEX.search(name):
            continue

        # Filter obvious templating or placeholders
        if "${" in val or "{{" in val:
            continue

        line = text.count("\n", 0, m.start()) + 1
        excerpt = text.splitlines()[line - 1].strip() if line - 1 < len(text.splitlines()) else ""
        findings.append(Finding("suspicious_assignment", str(path), line, f"Suspicious assignment to '{name}'", excerpt[:240]))

    return findings


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Scan a directory for potential secrets, unused defined secrets, and referenced-but-undefined secrets."
    )
    parser.add_argument("root", nargs="?", default=".", help="Root directory to scan (default: current directory)")
    parser.add_argument("--json", action="store_true", help="Output results as JSON")
    parser.add_argument("--full-path", action="store_true", help="Use absolute paths instead of relative paths")
    parser.add_argument("--max-bytes", type=int, default=2_000_000, help="Max file size to read (default: 2,000,000)")
    parser.add_argument("--exclude-dir", action="append", default=[], help="Directory name to exclude (repeatable)")
    parser.add_argument("--ignore-var", action="append", default=[], help="Variable name to ignore (repeatable)")
    args = parser.parse_args()

    root = Path(args.root).resolve()
    if not root.exists():
        print(f"Root path does not exist: {root}", file=sys.stderr)
        return 2

    exclude_dirs = set(DEFAULT_EXCLUDE_DIRS) | set(args.exclude_dir)
    ignore_names = set(DEFAULT_IGNORE_VAR_NAMES) | {n.lower() for n in args.ignore_var}

    findings: List[Finding] = []
    referenced: DefaultDict[str, Set[str]] = defaultdict(set)
    defined: Set[str] = set()
    files_scanned = 0

    for path in iter_files(root, DEFAULT_EXTENSIONS, exclude_dirs):
        text = safe_read_text(path, max_bytes=args.max_bytes)
        if text is None:
            continue

        files_scanned += 1
        findings.extend(scan_text_for_potential_secrets(text, path))

        # collect definitions from definition sources only
        if path.name in DEFINE_FILE_NAMES or path.suffix.lower() in DEFINE_FILE_SUFFIXES:
            for m in ENV_DEFINE.finditer(text):
                name = m.group("name")
                if not ignore_var(name, ignore_names):
                    defined.add(name)
            for m in YAML_DEFINE.finditer(text):
                name = m.group("name")
                if not ignore_var(name, ignore_names):
                    defined.add(name)

        # collect references (ALL-CAPS only)
        for pat in REF_PATTERNS:
            for m in pat.finditer(text):
                name = m.group("name")
                if ignore_var(name, ignore_names):
                    continue
                if not re.fullmatch(r"[A-Z][A-Z0-9_]+", name):
                    continue
                referenced[name].add(str(path))

    unused = {v for v in (defined - set(referenced.keys())) if SECRET_NAME_REGEX.search(v)}
    missing = set(referenced.keys()) - defined

    if args.json:
        output = {
            "scan_root": str(root),
            "files_scanned": files_scanned,
            "potential_secrets": [
                {**asdict(f), "path": format_path(f.path, root, args.full_path)}
                for f in findings
            ],
            "unused_secrets": sorted(unused),
            "referenced_but_not_defined": {
                k: sorted(format_path(p, root, args.full_path) for p in referenced[k])
                for k in sorted(missing)
            },
        }
        print(json.dumps(output, indent=2))
    else:
        print(f"Scanned: {root}")
        print(f"Files scanned: {files_scanned}")

        print("\nPotential secrets / suspicious values:")
        print("  none found" if not findings else "")
        for f in findings:
            p = format_path(f.path, root, args.full_path)
            print(f"  [{f.kind}] {p}:{f.line} {f.detail}")

        print("\nUnused secrets (defined but not referenced):")
        print("  none found" if not unused else "")
        for v in sorted(unused):
            print(f"  {v}")

        print("\nReferenced but not defined:")
        print("  none found" if not missing else "")
        for k in sorted(missing):
            print(f"  {k}:")
            for p in sorted(referenced[k]):
                print(f"    - {format_path(p, root, args.full_path)}")

    return 1 if findings or missing else 0


if __name__ == "__main__":
    raise SystemExit(main())
