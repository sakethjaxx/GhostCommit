#!/usr/bin/env python3
"""GhostCommit core: stdlib-only, report-only audit of AI-generated diffs.

    python audit.py [--task T] [--base REF] [--json] [--sarif PATH] [--fail-on N] [--verbose]

Looks at staged changes; if nothing is staged, at the working tree plus untracked files.
Never modifies the repo. Needs git and Python >= 3.11.
"""
from __future__ import annotations

import argparse
import ast
import fnmatch
import importlib.util
import json
import os
import re
import subprocess
import sys
import time
import tomllib
from collections import Counter
from dataclasses import asdict, dataclass, field
from pathlib import Path

try:  # optional: tree-sitter symbol diff for JS/TS/Go; regex fallback when absent
    import symbols_ts
except ImportError:
    symbols_ts = None

VERSION = "0.1.0"
EMPTY_TREE = "4b825dc642cb6eb9a060e54bf8d69288fbee4904"

# kind: (points per hit, cap per finding, cap across the diff, description)
KINDS = {
    "lost_error_handling": (30, 30, 60, "Error handling (try/except/catch/err checks) was removed"),
    "swallowed_error": (20, 20, 40, "Exception swallowed silently (except: pass / empty catch)"),
    "removed_guard": (12, 12, 36, "Early-return/raise guard clause was removed"),
    "removed_raise": (10, 10, 30, "raise/assert statements were removed"),
    "gutted_body": (30, 30, 60, "Function body replaced with a stub"),
    "placeholder": (30, 30, 60, "Truncation placeholder or stub left in code"),
    "deleted_function": (10, 10, 30, "Function or class deleted"),
    "signature_changed": (8, 8, 24, "Function signature changed (callers may break)"),
    "syntax_error": (25, 25, 50, "File no longer parses"),
    "muzzled_tooling": (6, 18, 30, "Linter/type-checker suppression added"),
    "removed_assertions": (4, 20, 40, "Test assertions removed"),
    "skipped_tests": (15, 30, 45, "Tests skipped/disabled/focused"),
    "deleted_test_file": (20, 20, 40, "Test file deleted"),
    "deleted_file": (8, 8, 24, "File deleted"),
    "secret": (40, 40, 80, "Possible hardcoded secret"),
    "phantom_import": (12, 12, 36, "Import does not resolve to stdlib, installed or declared dependency"),
    "dropped_types": (2, 8, 10, "Type annotations dropped"),
    "dropped_comments": (2, 10, 10, "Comments/docstrings dropped"),
    "magic_value": (3, 12, 15, "Hardcoded numeric/URL literal"),
    "quiet_risk": (6, 15, 18, "Dependency/CI/infra/config file changed"),
    "hidden_edits": (8, 8, 16, "Reformatting noise buries real edits"),
    "off_spec_hint": (8, 8, 24, "File shares no vocabulary with the task (weak signal)"),
    "diff_size": (10, 10, 10, "Very large diff (review fatigue)"),
    # advisory: small open models hallucinate, so LLM findings stay lighter than deterministic ones
    "llm_off_spec": (10, 10, 20, "LLM judged this file unrelated to the task"),
    "llm_regression": (8, 8, 24, "LLM flagged a semantic regression"),
}

# Weak/advisory signals: together they add at most thresholds.weak_cap points, so RED needs a strong signal.
WEAK = {"off_spec_hint", "magic_value", "quiet_risk", "dropped_types", "dropped_comments", "diff_size", "hidden_edits", "llm_off_spec", "llm_regression"}
DEFAULT_CFG = {"fail_on": None, "ignore": [], "thresholds": {"yellow": 30, "red": 60, "weak_cap": 35}, "weights": {}, "llm": {}}

PY, TS = {".py"}, {".ts", ".tsx"}
JS = {".js", ".jsx", ".mjs", ".cjs"} | TS
CODE = PY | JS | {".go", ".java", ".kt", ".rs", ".rb", ".php", ".cs", ".c", ".cc", ".cpp", ".h", ".hpp", ".swift", ".scala", ".sh", ".lua"}
HASH = {".py", ".rb", ".sh", ".yml", ".yaml", ".toml", ".r", ".pl"}

SUPPRESS = re.compile(r"ghostcommit:\s*ok")
GENERATED = re.compile(r"(^|/)(node_modules|dist|build|vendor|\.venv|__pycache__)/|\.min\.(js|css)$|\.(snap|map|svg|png|jpe?g|gif|ico|woff2?|pdf)$")
TEST = re.compile(r"(^|/)(tests?|__tests__|specs?)/|(^|/)test_[^/]*\.py$|_test\.(py|go|rb)$|\.(test|spec)\.[jt]sx?$|(^|/)conftest\.py$")
QUIET = [
    (re.compile(r"(^|/)(package-lock\.json|yarn\.lock|pnpm-lock\.yaml|poetry\.lock|uv\.lock|Cargo\.lock|go\.sum|Gemfile\.lock|composer\.lock)$"), "lockfile", 3),
    (re.compile(r"(^|/)(package\.json|pyproject\.toml|requirements[^/]*\.txt|go\.mod|Cargo\.toml|Gemfile|setup\.py|setup\.cfg|Pipfile)$"), "dependency manifest", 6),
    (re.compile(r"(^|/)(\.github/workflows/|\.gitlab-ci\.yml|Jenkinsfile|azure-pipelines|\.circleci/)"), "CI config", 6),
    (re.compile(r"(^|/)(Dockerfile[^/]*|docker-compose[^/]*|[^/]+\.tf|\.pre-commit-config\.yaml|\.ghostcommit\.toml)$"), "infra/audit config", 6),
    (re.compile(r"(^|/)\.env[^/]*$"), "env file", 15),
]

HUNK = re.compile(r"^@@ -(\d+)(?:,\d+)? \+(\d+)(?:,\d+)? @@ ?(.*)$")
EH = re.compile(r"^\s*(?:\}\s*)?(?:try|catch|except|rescue|finally|raise|throw|assert)\b|\.catch\(|\bif\s+err\s*!=\s*nil\b")
SWALLOW_PY = re.compile(r"except[^\n:]*:[ \t]*(?:\n[ \t]*)?(?:pass|\.\.\.)[ \t]*(?:\n|$)")
SWALLOW_JS = re.compile(r"catch\s*(?:\([^)]*\))?\s*\{\s*(?://[^\n]*\n\s*)*\}|\.catch\(\s*(?:\([^)]*\)|\w*)\s*=>\s*\{\s*\}\s*\)")
PLACEHOLDER = re.compile(
    r"(?i)(?:\.{3}|…)\s*\(?\s*(?:existing|rest of|remaining|previous|unchanged|same as before)\b"
    r"|\b(?:rest|remainder) of (?:the )?(?:file|code|function|class|method|implementation|logic)\b"
    r"|\b(?:existing|previous|original) (?:code|implementation|logic) (?:here|unchanged|remains|omitted)"
    r"|\bcode (?:omitted|unchanged|remains the same)\b|\bsame as before\b|\bimplementation (?:omitted|elided)\b"
)
TODO_STUB = re.compile(r"(?i)\b(?:todo|fixme)\b[:\s-]*(?:implement|fill in|add (?:logic|code)|complete)\b")
MUZZLE = re.compile(r"#\s*(?:type:\s*ignore|noqa|pylint:\s*disable|nosec|fmt:\s*off)|eslint-disable|@ts-(?:ignore|nocheck|expect-error)|//\s*nolint|#\[allow\(|NOSONAR")
ASSERT = re.compile(r"\b(?:assert\w*|expect)\b")
SKIP = re.compile(r"@pytest\.mark\.(?:skip|xfail)|pytest\.skip\(|@unittest\.skip|\b(?:xit|xdescribe|xtest)\(|\b(?:it|test|describe)\.(?:skip|only)\(|\.only\(|\bt\.Skip\(|@Disabled|@Ignore\b")
SIG = re.compile(r"\b(?:def|function|func|fn)\b|=>")
ANN = re.compile(r"\w\??\s*:\s*[A-Za-z_\[{(<]|->|\)\s*:\s*[A-Za-z_]")
CONST_DEF = re.compile(r"^\s*(?:export\s+)?(?:const\s+)?[A-Z][A-Z0-9_]+\s*[:=]")
NUM = re.compile(r"(?<![\w.#$-])\d{3,}(?![\w.])")
URL = re.compile(r"https?://[^\s\"'`)>]+")
URL_OK = re.compile(r"localhost|127\.0\.0\.1|example\.(?:com|org)|w3\.org|json-schema|schemas?\.|github\.com|docs?\.")
COMMON_NUMS = {100, 200, 201, 204, 255, 256, 301, 302, 304, 400, 401, 403, 404, 409, 422, 429, 500, 502, 503, 512, 1000, 1024, 2048, 3000, 4096, 5000, 8000, 8080}
STRIP_STR = re.compile(r"\"[^\"\n]*\"|'[^'\n]*'")
SECRETS = [
    re.compile(r"(?i)((?:api[_-]?key|secret|token|passwd|password|private[_-]?key|access[_-]?key)\w*[\"']?\s*[:=]\s*[\"'])([^\"'\s]{8,})([\"'])"),
    re.compile(r"\b(AKIA[0-9A-Z]{16}|gh[pos]_[A-Za-z0-9]{36}|sk-[A-Za-z0-9_-]{20,}|xox[baprs]-[A-Za-z0-9-]{10,})\b"),
    re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?(?:-----END [A-Z ]*PRIVATE KEY-----|$)"),
]
FAKE_VAL = re.compile(r"(?i)^(?:your|xxx|changeme|example|placeholder|dummy|fake|test|<|\$\{|\{\{|\*\*\*)")
PY_IMPORT = re.compile(r"^\s*(?:from\s+(\.*)([\w.]*)\s+import\b|import\s+(.+))")
JS_IMPORT = re.compile(r"(?:\bfrom\s+|\bimport\s*\(?\s*|\brequire\(\s*)['\"]([^'\"]+)['\"]")
NODE_BUILTINS = set("fs path os http https http2 crypto util stream events url child_process zlib readline assert buffer net tls dns cluster worker_threads perf_hooks process module vm v8 string_decoder querystring timers tty dgram constants inspector repl punycode".split())
STOP = {"that", "this", "with", "from", "into", "code", "file", "files", "change", "changes", "please", "should", "want", "need", "using", "make", "update", "feature"}
FUNC = (ast.FunctionDef, ast.AsyncFunctionDef)
TRY = (ast.Try, getattr(ast, "TryStar", ast.Try))
TERMINAL = (ast.Return, ast.Raise, ast.Continue, ast.Break)
DECL = re.compile(r"\b(?:def|class|function|func|fn|interface|struct|enum|trait|impl|type)\s+(?:\([^)]*\)\s*)?([A-Za-z_$][\w$]*)")
ARROW = re.compile(r"\b([A-Za-z_$][\w$]*)\s*[:=]\s*(?:async\s*)?(?:function\b|\([^)]*\)\s*(?::[^=]+)?=>)")
CTX_NAME = re.compile(r"\s*(?:async\s+)?([A-Za-z_$][\w$]*)\s*\(")


@dataclass
class Change:
    path: str
    status: str = "M"  # A M D R
    old_path: str = ""
    added: list = field(default_factory=list)  # (lineno, text)
    removed: list = field(default_factory=list)
    ctx: set = field(default_factory=set)
    patch: list = field(default_factory=list)
    binary: bool = False


@dataclass
class Finding:
    kind: str
    file: str
    line: int
    why: str
    symbol: str = ""
    lines: list = field(default_factory=list)
    points: int = 0


def git(repo, *args):
    r = subprocess.run(["git", "-C", str(repo), "-c", "core.quotepath=off", *args], capture_output=True)
    return r.stdout.decode("utf-8", "replace") if r.returncode == 0 else None


def redact(text):
    text = SECRETS[0].sub(lambda m: m[1] + "***REDACTED***" + m[3], text)
    return SECRETS[2].sub("***REDACTED PRIVATE KEY***", SECRETS[1].sub("***REDACTED***", text))


def is_comment(line, ext):
    t = line.strip()
    if ext in HASH:
        return t.startswith("#") and not t.startswith("#!") or (ext == ".py" and t.startswith(('"""', "'''")))
    return t.startswith(("//", "/*", "*"))


def parse_diff(text):
    changes, cur, in_hunk, old_no, new_no = [], None, False, 0, 0
    for line in text.split("\n"):
        if line.startswith("diff --git "):
            m = re.match(r"diff --git a/(.+) b/\1$", line) or re.match(r"diff --git a/(.+) b/(.+)$", line)
            cur = Change(m.group(m.lastindex))
            changes.append(cur)
            in_hunk = False
            continue
        if cur is None:
            continue
        cur.patch.append(line)
        if not in_hunk or line.startswith("@@"):
            m = HUNK.match(line)
            if m:
                in_hunk, old_no, new_no = True, int(m[1]), int(m[2])
                if m[3].strip():
                    cur.ctx.add(m[3].strip())
            elif line.startswith("new file mode"):
                cur.status = "A"
            elif line.startswith("deleted file mode"):
                cur.status = "D"
            elif line.startswith("rename from "):
                cur.status, cur.old_path = "R", line[12:]
            elif line.startswith("rename to "):
                cur.path = line[10:]
            elif line.startswith(("Binary files", "GIT binary patch")):
                cur.binary = True
        elif line.startswith("+"):
            cur.added.append((new_no, line[1:]))
            new_no += 1
        elif line.startswith("-"):
            cur.removed.append((old_no, line[1:]))
            old_no += 1
        elif line.startswith(" "):
            old_no += 1
            new_no += 1
    return changes


def decl_names(lines):
    out = set()
    for _, t in lines:
        m = DECL.search(t) or ARROW.search(t)
        if m:
            out.add(m[1])
    return out


# ---------- python AST helpers ----------
def _own(fn):
    """Statements/exprs directly in fn, not descending into nested defs."""
    stack = list(fn.body)
    while stack:
        n = stack.pop()
        if isinstance(n, FUNC + (ast.ClassDef,)):
            continue
        yield n
        stack.extend(ast.iter_child_nodes(n))


def _funcs(tree):
    out = {}

    def walk(node, prefix):
        for c in ast.iter_child_nodes(node):
            if isinstance(c, FUNC + (ast.ClassDef,)):
                out[prefix + c.name] = c
                walk(c, prefix + c.name + ".")
            else:
                walk(c, prefix)

    walk(tree, "")
    return out


def _trivial(n):
    if isinstance(n, (ast.Pass, ast.Expr)) and (isinstance(n, ast.Pass) or isinstance(n.value, ast.Constant)):
        return True
    if isinstance(n, ast.Raise) and n.exc is not None:
        e = n.exc.func if isinstance(n.exc, ast.Call) else n.exc
        return isinstance(e, ast.Name) and e.id == "NotImplementedError"
    return False


def _feat(fn):
    ns = list(_own(fn))
    hs = [h for n in ns if isinstance(n, TRY) for h in n.handlers]
    a = getattr(fn, "args", None)
    args = a.posonlyargs + a.args + a.kwonlyargs + [x for x in (a.vararg, a.kwarg) if x] if a else []
    return {
        "handlers": len(hs),
        "swallowed": sum(all(_trivial(s) and not isinstance(s, ast.Raise) for s in h.body) for h in hs),
        "raises": sum(isinstance(n, (ast.Raise, ast.Assert)) for n in ns),
        "guards": sum(isinstance(n, ast.If) and isinstance(n.body[-1], TERMINAL) for n in ns),
        "ann": sum(x.annotation is not None for x in args) + (getattr(fn, "returns", None) is not None),
        "sig": ([x.arg for x in args], len(a.defaults) + sum(d is not None for d in a.kw_defaults)) if a else None,
        "stmts": sum(isinstance(n, ast.stmt) and not _trivial(n) for n in ns),
    }


def _parse(src):
    try:
        return ast.parse(src) if src is not None else None
    except (SyntaxError, ValueError):
        return None


def py_syms(tree):
    out = {
        q: {"kind": "class" if isinstance(n, ast.ClassDef) else "function", "line": n.lineno, "end": n.end_lineno,
            "dump": ast.dump(n), "feat": None if isinstance(n, ast.ClassDef) else _feat(n)}
        for q, n in _funcs(tree).items()
    }
    out["<module>"] = {"kind": "module", "line": 1, "end": 1, "dump": "", "feat": _feat(tree)}
    return out


class Audit:
    def __init__(self, repo, cfg):
        self.repo, self.cfg = repo, cfg
        w = cfg["weights"]  # a configured weight also lifts that kind's caps, or it would be silently clamped
        self.kinds = {k: (w.get(k, v[0]), max(v[1], w.get(k, 0)), max(v[2], w.get(k, 0)), v[3]) for k, v in KINDS.items()}
        self.findings: list[Finding] = []
        self.mode = "staged"
        self.old_ref = "HEAD"
        self._deps: dict = {}

    # ----- findings -----
    def add(self, kind, file, line, why, symbol="", n=1, lines=None, points=None):
        base, cap, _, _ = self.kinds[kind]
        pts = min(points if points is not None else base * n, cap)
        self.findings.append(Finding(kind, file, line, redact(why), symbol, lines or [line], pts))

    # ----- acquisition -----
    def collect(self, base):
        flags = ("diff", "--no-color", "--no-ext-diff", "-U3", "--find-renames")
        has_head = git(self.repo, "rev-parse", "--verify", "-q", "HEAD") is not None
        head = "HEAD" if has_head else EMPTY_TREE
        untracked = []
        if base:
            mb = (git(self.repo, "merge-base", base, "HEAD") or base).strip()
            self.mode, self.old_ref = "base", mb
            text = git(self.repo, *flags, mb, "HEAD") or ""
        else:
            text = git(self.repo, *flags, "--cached") or ""
            self.old_ref = head
            if not text.strip():
                self.mode = "worktree"
                text = git(self.repo, *flags, head) or ""
                untracked = [p for p in (git(self.repo, "ls-files", "-o", "--exclude-standard", "-z") or "").split("\0") if p]
        changes = parse_diff(text)
        for p in untracked:
            fp = self.repo / p
            try:
                raw = fp.read_bytes()
            except OSError:
                continue
            if b"\0" in raw[:8192] or len(raw) > 512_000:
                continue
            lines = raw.decode("utf-8", "replace").splitlines()
            changes.append(Change(p, "A", added=[(i + 1, l) for i, l in enumerate(lines)], patch=["+" + l for l in lines]))
        ign = self.cfg["ignore"]
        return [c for c in changes if not any(fnmatch.fnmatch(c.path, g) for g in ign)]

    def old_src(self, ch):
        if ch.status == "A":
            return None
        return git(self.repo, "show", f"{self.old_ref}:{ch.old_path or ch.path}")

    def new_src(self, ch):
        if ch.status == "D":
            return None
        if self.mode == "worktree":
            try:
                return (self.repo / ch.path).read_text("utf-8", errors="replace")
            except OSError:
                return None
        return git(self.repo, "show", (":" if self.mode == "staged" else "HEAD:") + ch.path)

    # ----- dependency lookup -----
    def py_declared(self):
        if "py" not in self._deps:
            names = set()
            norm = lambda s: re.split(r"[\s\[<>=!~;@(]", s.strip(), maxsplit=1)[0].lower().replace("-", "_").replace(".", "_")
            try:
                d = tomllib.loads((self.repo / "pyproject.toml").read_text("utf-8"))
                proj = d.get("project", {})
                names |= {norm(x) for x in proj.get("dependencies", [])}
                for v in proj.get("optional-dependencies", {}).values():
                    names |= {norm(x) for x in v}
                for v in d.get("dependency-groups", {}).values():
                    names |= {norm(x) for x in v if isinstance(x, str)}
                names |= {k.lower().replace("-", "_") for k in d.get("tool", {}).get("poetry", {}).get("dependencies", {})}
            except (OSError, tomllib.TOMLDecodeError):
                pass
            for f in self.repo.glob("requirements*.txt"):
                try:
                    names |= {norm(l) for l in f.read_text("utf-8").splitlines() if l.strip() and not l.lstrip().startswith(("#", "-"))}
                except OSError:
                    pass
            self._deps["py"] = names
        return self._deps["py"]

    def js_declared(self, path):
        d = (self.repo / path).parent
        while True:
            pj = d / "package.json"
            if pj.exists():
                if pj not in self._deps:
                    try:
                        j = json.loads(pj.read_text("utf-8"))
                        self._deps[pj] = {k for s in ("dependencies", "devDependencies", "peerDependencies", "optionalDependencies") for k in j.get(s, {})}
                    except (OSError, ValueError):
                        self._deps[pj] = None
                return self._deps[pj]
            if d == self.repo or d == d.parent:
                return None
            d = d.parent

    @staticmethod
    def pep723_deps(src):
        """Dependencies declared in a `# /// script` inline-metadata block (uv/pipx run scripts)."""
        m = re.search(r"(?m)^# /// script\n((?:#.*\n)+?)# ///$", src or "")
        try:
            deps = tomllib.loads("".join(l[2:] if l.startswith("# ") else l[1:] for l in m[1].splitlines(True))).get("dependencies", []) if m else []
        except tomllib.TOMLDecodeError:
            return set()
        return {re.split(r"[\s\[<>=!~;@(]", d.strip(), maxsplit=1)[0].lower().replace("-", "_").replace(".", "_") for d in deps}

    def py_resolves(self, top, level, path, extra=frozenset()):
        here = (self.repo / path).parent
        if level:
            base = here
            for _ in range(level - 1):
                base = base.parent
            return not top or (base / f"{top}.py").exists() or (base / top).is_dir()
        if top in sys.stdlib_module_names:
            return True
        if any((self.repo / p).exists() for p in (f"{top}.py", top, f"src/{top}", f"src/{top}.py")) or (here / f"{top}.py").exists() or (here / top).is_dir():
            return True
        try:
            if importlib.util.find_spec(top):
                return True
        except (ImportError, ValueError, AttributeError):
            pass
        return top.lower().replace("-", "_") in self.py_declared() | extra

    def phantom_imports(self, ch, A, ext, tree, extra=frozenset()):
        in_try = set()
        if tree:
            for t in (n for n in ast.walk(tree) if isinstance(n, TRY)):
                in_try |= {n.lineno for n in ast.walk(t) if isinstance(n, (ast.Import, ast.ImportFrom))}
        for no, t in A:
            if ext in PY and no not in in_try and (m := PY_IMPORT.match(t)):
                mods = [(len(m[1]), m[2].split(".")[0])] if m[2] is not None and m[0].lstrip().startswith("from") else [(0, p.strip().split(" as ")[0].split(".")[0]) for p in m[3].split(",") if p.strip()]
                for level, top in mods:
                    if (top or level) and re.fullmatch(r"\w*", top) and not self.py_resolves(top, level, ch.path, extra):
                        self.add("phantom_import", ch.path, no, f"import '{'.' * level}{top}' resolves to nothing (not stdlib, installed, local or declared; check your env before trusting)")
            elif ext in JS and (m := JS_IMPORT.search(t)) and not is_comment(t, ext):
                spec = m[1]
                if spec.startswith((".", "/", "node:", "@/", "~", "#", "http")):
                    continue
                pkg = "/".join(spec.split("/")[: 2 if spec.startswith("@") else 1])
                declared = self.js_declared(ch.path)
                if declared is None or pkg in NODE_BUILTINS or pkg in declared or f"@types/{pkg}" in declared:
                    continue
                if (self.repo / "node_modules" / pkg).exists() or any((self.repo / b / pkg.split("/")[0]).exists() or list((self.repo / b).glob(pkg.split("/")[0] + ".*")) for b in ("src", ".")):
                    continue
                self.add("phantom_import", ch.path, no, f"import '{pkg}' is not in package.json or node_modules")

    # ----- python symbol diff -----
    def feature_findings(self, path, q, line, fo, fn_, real):
        pts = lambda key, v: v if real[key] else max(1, v // 2)
        moved = "" if real["handlers"] else " (file total unchanged, maybe moved)"
        if fo["handlers"] > fn_["handlers"]:
            self.add("lost_error_handling", path, line, f"{q}: lost error handling ({fo['handlers']}->{fn_['handlers']} try/except/catch handlers){moved}", q, points=pts("handlers", 30))
        if fn_["swallowed"] > fo["swallowed"]:
            self.add("swallowed_error", path, line, f"{q}: exception swallowed (except: pass)", q)
        if fo["raises"] > fn_["raises"] and not TEST.search(path):  # tests: removed_assertions already covers this
            self.add("removed_raise", path, line, f"{q}: {fo['raises'] - fn_['raises']} raise/assert removed", q, points=pts("raises", 10))
        if fo["guards"] > fn_["guards"]:
            self.add("removed_guard", path, line, f"{q}: {fo['guards'] - fn_['guards']} guard clause(s) removed", q, points=pts("guards", 12))
        if fo["ann"] > fn_["ann"]:
            self.add("dropped_types", path, line, f"{q}: {fo['ann'] - fn_['ann']} type annotation(s) dropped", q, n=fo["ann"] - fn_["ann"])
        if fo["sig"] and fn_["sig"] and fo["sig"] != fn_["sig"]:
            self.add("signature_changed", path, line, f"{q}: signature {fo['sig'][0]}+{fo['sig'][1]}dflt -> {fn_['sig'][0]}+{fn_['sig'][1]}dflt", q)
        if fo["stmts"] >= 3 and fn_["stmts"] == 0 and fn_["sig"]:
            self.add("gutted_body", path, line, f"{q}: {fo['stmts']} statements replaced by a stub", q)

    def compare(self, path, old, new, nlines):
        """old/new: qualname -> {kind: func|class|module, line, end, dump, feat}. Shared by python (ast) and tree-sitter."""
        names = lambda d: {q for q in d if q != "<module>"}
        removed = sorted(names(old) - names(new))
        sym = {"added": sorted(names(new) - names(old)), "removed": removed, "changed": []}
        for q in removed:
            if not any(q.startswith(r + ".") for r in removed):
                self.add("deleted_function", path, old[q]["line"], f"{old[q]['kind']} {q} deleted (was line {old[q]['line']} in old file)", q)
        tot = lambda d, k: sum(v["feat"][k] for v in d.values() if v["feat"])
        real = {k: tot(old, k) > tot(new, k) for k in ("handlers", "raises", "guards")}
        for q in sorted(old.keys() & new.keys()):
            o, n = old[q], new[q]
            if q != "<module>":
                if "class" in (o["kind"], n["kind"]) or o["dump"] == n["dump"]:
                    continue
                sym["changed"].append(q)
                if any(SUPPRESS.search(l) for l in nlines[n["line"] - 1 : n["end"]]):
                    continue
            if o["feat"] and n["feat"]:
                self.feature_findings(path, q, n["line"], o["feat"], n["feat"], real)
        return sym

    def py_check(self, ch, old, new):
        try:
            nt = ast.parse(new)
        except (SyntaxError, ValueError) as e:
            if _parse(old) is not None:
                self.add("syntax_error", ch.path, getattr(e, "lineno", None) or 1, f"no longer parses: {getattr(e, 'msg', e)}")
            return None, None
        ns, ot = py_syms(nt), _parse(old)
        if ot is None:
            return nt, {"added": sorted(q for q in ns if q != "<module>"), "removed": [], "changed": []}
        return nt, self.compare(ch.path, py_syms(ot), ns, new.splitlines())

    def ts_check(self, ch, old, new, ext):
        """tree-sitter symbol diff for JS/TS/Go; None when unavailable (caller falls back to regex)."""
        ns = symbols_ts.analyze(ext, new) if symbols_ts else None
        if ns is None:
            return None
        os_ = symbols_ts.analyze(ext, old) if old is not None else None
        if os_ is None:
            return {"added": sorted(ns), "removed": [], "changed": []}
        return self.compare(ch.path, os_, ns, new.splitlines())

    # ----- per-file checks -----
    def check_file(self, ch):
        path, ext = ch.path, Path(ch.path).suffix.lower()
        A = [(n, t) for n, t in ch.added if not SUPPRESS.search(t)]
        R = [(n, t) for n, t in ch.removed if not SUPPRESS.search(t)]
        is_test = bool(TEST.search(path))
        sym = None
        if ch.status == "D":
            if is_test:
                self.add("deleted_test_file", path, 1, f"test file deleted ({len(ch.removed)} lines)")
            else:
                self.add("deleted_file", path, 1, f"file deleted ({len(ch.removed)} lines)")
            if ext in PY and (old := self.old_src(ch)) and (ot := _parse(old)):
                sym = {"added": [], "removed": sorted(_funcs(ot)), "changed": []}
            return sym
        for rx, label, pts in QUIET:
            if rx.search(path):
                self.add("quiet_risk", path, 1, f"{label} changed", points=pts)
                break
        if GENERATED.search(path) or ch.binary or QUIET[0][0].search(path):
            return None

        tree = None
        if ext in PY:
            old, new = self.old_src(ch), self.new_src(ch)
            if new is not None:
                tree, sym = self.py_check(ch, old, new)
        elif ext in JS | {".go"} and (new := self.new_src(ch)) is not None:
            sym = self.ts_check(ch, self.old_src(ch), new, ext)
        elif ext in {".json", ".toml"} and (new := self.new_src(ch)) is not None and (old := self.old_src(ch)) is not None:
            load = json.loads if ext == ".json" else tomllib.loads
            try:
                load(old)
                try:
                    load(new)
                except Exception as e:  # noqa: BLE001 - any parse failure counts
                    self.add("syntax_error", path, 1, f"no longer parses: {str(e)[:80]}")
            except Exception:  # noqa: BLE001 - old was already broken
                pass
        structured = sym is not None  # python ast or tree-sitter handled error-handling/types; skip the regex versions
        if sym is None and ext in CODE:
            names_a, names_r = decl_names(A), decl_names(R)
            ctx = {m[1] for c in ch.ctx if (m := DECL.search(c) or ARROW.search(c) or CTX_NAME.match(c))}
            sym = {"added": sorted(names_a - names_r), "removed": sorted(names_r - names_a), "changed": sorted((names_a & names_r) | (ctx - names_a - names_r))}

        # error handling, regex path (non-python, or python that failed to parse)
        if ext in CODE and not structured:
            lost =sum(bool(EH.search(t)) and not is_comment(t, ext) for _, t in R) - sum(bool(EH.search(t)) and not is_comment(t, ext) for _, t in A)
            if lost > 0:
                self.add("lost_error_handling", path, R[0][0] if R else 1, f"{lost} net error-handling line(s) removed (try/catch/throw/err checks)", points=10 * min(lost, 3))
            text = "\n".join(t for _, t in A)
            rx = SWALLOW_PY if ext in PY else SWALLOW_JS
            for m in rx.finditer(text):
                self.add("swallowed_error", path, A[text[: m.start()].count("\n")][0], "exception swallowed (empty catch / except: pass)")
        # placeholders
        if ext in CODE:
            hits = [n for n, t in A if PLACEHOLDER.search(t)]
            if hits:
                self.add("placeholder", path, hits[0], "truncation placeholder in code (LLM elided content)", lines=hits)
            todo = [n for n, t in A if TODO_STUB.search(t)]
            if todo:
                self.add("placeholder", path, todo[0], "TODO stub left in new code", lines=todo, points=8)
        # muzzled tooling
        mz = [n for n, t in A if ext in CODE and MUZZLE.search(t)]
        if mz:
            self.add("muzzled_tooling", path, mz[0], f"{len(mz)} linter/type-check suppression(s) added", n=len(mz), lines=mz)
        # secrets
        for n, t in A:
            m = SECRETS[0].search(t)
            if (m and not FAKE_VAL.match(m[2])) or SECRETS[1].search(t) or SECRETS[2].search(t):
                self.add("secret", path, n, "possible hardcoded secret" + (f" ({m[1].strip(chr(34) + chr(39) + ' :=')})" if m else ""))
        # tests
        if is_test:
            rem = sum(bool(ASSERT.search(t)) for _, t in R) - sum(bool(ASSERT.search(t)) for _, t in A)
            if rem > 0:
                self.add("removed_assertions", path, R[0][0] if R else 1, f"{rem} net assertion(s) removed", n=rem)
            sk = [n for n, t in A if SKIP.search(t)]
            if sk:
                self.add("skipped_tests", path, sk[0], f"{len(sk)} test(s) skipped/disabled/focused", n=len(sk), lines=sk)
        # types/comments
        if (ext in TS and not structured) or (ext in PY and tree is None):
            ann = lambda L: sum(len(ANN.findall(t)) for _, t in L if SIG.search(t))
            if ann(R) > ann(A):
                self.add("dropped_types", path, R[0][0], f"{ann(R) - ann(A)} type annotation(s) dropped", n=ann(R) - ann(A))
        if ext in CODE:
            dc = sum(is_comment(t, ext) for _, t in R) - sum(is_comment(t, ext) for _, t in A)
            if dc >= 3:
                self.add("dropped_comments", path, R[0][0], f"{dc} net comment/docstring line(s) dropped", n=dc)
        # magic values
        if ext in CODE and not is_test:
            vals, ln = [], []
            for n, t in A:
                if is_comment(t, ext) or CONST_DEF.match(t):
                    continue
                v = [x for x in NUM.findall(STRIP_STR.sub('""', t)) if int(x) not in COMMON_NUMS]
                v += [u for u in URL.findall(t) if not URL_OK.search(u)]
                if v:
                    vals += v
                    ln.append(n)
            if vals:
                self.add("magic_value", path, ln[0], f"hardcoded literal(s): {', '.join(vals[:3])}", n=len(vals), lines=ln)
        # phantom imports
        if ext in PY | JS:
            self.phantom_imports(ch, A, ext, tree, self.pep723_deps(self.new_src(ch)) if ext in PY else frozenset())
        # reformat noise
        norm = lambda L: Counter("".join(t.split()) for _, t in L if t.strip())
        same = sum((norm(R) & norm(A)).values())
        real_n = len(A) + len(R) - 2 * same
        if same >= 10 and real_n > 0 and same * 2 >= real_n:
            self.add("hidden_edits", path, A[0][0] if A else 1, f"{same} reformatted/moved line(s) bury {real_n} real change(s)")
        return sym


# ---------- task / config / report ----------
def derive_task(repo, task):
    if task:
        return task, "flag"
    if v := os.environ.get("GHOSTCOMMIT_TASK"):
        return v.strip(), "env"
    p = (git(repo, "rev-parse", "--git-path", "ghostcommit/task") or "").strip()
    if p:
        try:
            f = repo / p
            if time.time() - f.stat().st_mtime < 86400 and (t := f.read_text("utf-8").strip()):  # older = stale session
                return t[:500], "hook"
        except OSError:
            pass
    b = (git(repo, "symbolic-ref", "--short", "-q", "HEAD") or "").strip()
    if b and b not in {"main", "master", "develop", "dev", "trunk"}:
        return re.sub(r"[-_/]+", " ", re.sub(r"^(?:feat|feature|fix|bugfix|hotfix|chore|refactor|docs|test|perf|ci)[/_-]", "", b)), "branch"
    return "", "none"


def load_cfg(repo, path=None):
    cfg = {k: (dict(v) if isinstance(v, dict) else v) for k, v in DEFAULT_CFG.items()}
    p = Path(path) if path else repo / ".ghostcommit.toml"
    try:
        user = tomllib.loads(p.read_text("utf-8"))
    except OSError:
        return cfg
    for k, v in user.items():
        if k not in cfg:
            continue
        if isinstance(cfg[k], dict) and isinstance(v, dict):
            cfg[k].update(v)
        else:
            cfg[k] = v
    return cfg


def off_spec(a, changes, task, syms):
    toks = {t[:5] for t in re.findall(r"[a-z0-9]{4,}", task.lower()) if t not in STOP}
    if not toks or len(changes) < 2:
        return
    cand, hit = [], []
    for ch in changes:
        if ch.binary or GENERATED.search(ch.path) or any(rx.search(ch.path) for rx, *_ in QUIET[:1]) or ch.status == "D":
            continue
        hay = (ch.path + " " + " ".join(sum(syms.get(ch.path, {}).values(), [])) + " " + " ".join(t for _, t in ch.added + ch.removed)[:6000]).lower()
        (hit if any(t in hay for t in toks) else cand).append(ch.path)
    if hit:  # if nothing matched, the task text is too vague to judge
        for p in cand:
            a.add("off_spec_hint", p, 1, f"no overlap with task vocabulary ({', '.join(sorted(toks))[:60]})")


def run(repo=".", task=None, base=None, config=None, max_diff_chars=6000):
    top = git(Path(repo), "rev-parse", "--show-toplevel")
    if top is None:
        raise SystemExit("ghostcommit: not a git repository")
    repo = Path(top.strip())
    cfg = load_cfg(repo, config)
    a = Audit(repo, cfg)
    changes = a.collect(base)
    task, task_src = derive_task(repo, task)
    task = redact(task)  # prompts can contain pasted secrets; the task goes into reports and LLM requests
    syms = {}
    for ch in changes:
        s = a.check_file(ch)
        if s and any(s.values()):
            syms[ch.path] = s
    off_spec(a, changes, task, syms)
    n_add, n_rem = sum(len(c.added) for c in changes), sum(len(c.removed) for c in changes)
    if len(changes) > 15 or n_add + n_rem > 800:
        a.add("diff_size", "(diff)", 1, f"{len(changes)} files, +{n_add}/-{n_rem} lines")

    fpts = Counter()
    for f in a.findings:
        fpts[f.file] += f.points
    files, budget = [], 10 * max_diff_chars
    for ch in sorted(changes, key=lambda c: -fpts[c.path]):
        d = redact("\n".join(ch.patch))
        cut = len(d) > min(max_diff_chars, budget)
        d = d[: min(max_diff_chars, budget)] + ("\n... [truncated]" if cut else "")
        budget = max(0, budget - len(d))
        files.append({"path": ch.path, "status": ch.status, "added": len(ch.added), "removed": len(ch.removed), "points": fpts[ch.path], "diff": d})
    rep = {
        "version": VERSION, "mode": a.mode, "task": task, "task_source": task_src,
        "stats": {"files": len(changes), "added": n_add, "removed": n_rem},
        "fail_on": cfg["fail_on"], "thresholds": cfg["thresholds"], "weights": cfg["weights"],
        "findings": [asdict(f) for f in a.findings],
        "symbols": syms, "files": files, "llm": cfg["llm"],
    }
    return rescore(rep)


def new_finding(rep, kind, file, line, why):
    """Append a finding (e.g. from an LLM pass) to a finished report; call rescore() after."""
    base, cap, _, _ = KINDS[kind]
    w = rep["weights"].get(kind, base)
    rep["findings"].append(asdict(Finding(kind, file, line, redact(why), "", [line], min(w, max(cap, w)))))


def rescore(rep):
    by = {}
    for f in rep["findings"]:
        by.setdefault(f["kind"], []).append(f)
    rep["breakdown"] = sorted(
        ({"kind": k, "count": len(fs), "points": min(sum(f["points"] for f in fs), max(KINDS[k][2], rep["weights"].get(k, 0)))} for k, fs in by.items()),
        key=lambda b: -b["points"],
    )
    th = rep["thresholds"]
    weak = sum(b["points"] for b in rep["breakdown"] if b["kind"] in WEAK)
    rep["score"] = min(100, sum(b["points"] for b in rep["breakdown"] if b["kind"] not in WEAK) + min(weak, th["weak_cap"]))
    rep["band"] = "red" if rep["score"] >= th["red"] else "yellow" if rep["score"] >= th["yellow"] else "green"
    rep["findings"].sort(key=lambda f: -f["points"])
    rep["summary"] = summary(rep)
    return rep


def summary(rep):
    st, fs = rep["stats"], rep["findings"]
    task = f" | task: {rep['task'][:60]}" if rep["task"] else ""
    intent = f" | intent {rep['intent_match']}%" if rep.get("intent_match") is not None else ""
    l1 = f"RISK {rep['score']}/100 {rep['band'].upper()} | {st['files']} files +{st['added']}/-{st['removed']}{intent}{task}"
    l2 = f"Top: {fs[0]['why']} ({fs[0]['file']}:{fs[0]['line']})" + (f" +{len(fs) - 1} more" if len(fs) > 1 else "") if fs else "Top: no flags"
    l3 = {"red": "STOP: review the flagged items line-by-line before committing.",
          "yellow": "Skim the flagged items before committing.",
          "green": "No red flags. Normal review is enough."}[rep["band"]]
    return [l1, l2[:200], l3]


def sarif(rep):
    level = lambda p: "error" if p >= 20 else "warning" if p >= 8 else "note"
    return {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json", "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {"name": "ghostcommit", "version": VERSION, "rules": [{"id": k, "shortDescription": {"text": v[3]}} for k, v in KINDS.items()]}},
            "results": [{
                "ruleId": f["kind"], "level": level(f["points"]), "message": {"text": f["why"]},
                "locations": [{"physicalLocation": {"artifactLocation": {"uri": f["file"]}, "region": {"startLine": max(1, f["line"])}}}],
            } for f in rep["findings"]],
        }],
    }


def main(argv=None):
    ap = argparse.ArgumentParser(prog="audit.py", description="GhostCommit core audit (stdlib only, report-only).")
    ap.add_argument("--task", help="what the change was supposed to do")
    ap.add_argument("--base", help="audit REF...HEAD instead of local changes")
    ap.add_argument("--json", action="store_true", help="machine-readable report on stdout")
    ap.add_argument("--sarif", metavar="PATH", help="also write SARIF 2.1.0 to PATH")
    ap.add_argument("--fail-on", type=int, help="exit 1 when score >= N")
    ap.add_argument("--verbose", action="store_true")
    ap.add_argument("--config")
    ap.add_argument("--repo", default=".", help=argparse.SUPPRESS)
    ap.add_argument("--max-diff-chars", type=int, default=6000)
    args = ap.parse_args(argv)
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    rep = run(args.repo, args.task, args.base, args.config, args.max_diff_chars)
    if args.sarif:
        Path(args.sarif).write_text(json.dumps(sarif(rep), indent=2), "utf-8")
    if args.json:
        print(json.dumps(rep, indent=2, ensure_ascii=False))
    else:
        color = sys.stdout.isatty() and not os.environ.get("NO_COLOR")
        c = {"red": "31;1", "yellow": "33;1", "green": "32;1"}[rep["band"]]
        l = rep["summary"]
        print(f"\x1b[{c}m{l[0]}\x1b[0m" if color else l[0])
        print(l[1])
        print(l[2])
        if args.verbose:
            for b in rep["breakdown"]:
                print(f"  +{b['points']:>3}  {b['kind']} x{b['count']}")
            for f in rep["findings"]:
                print(f"  [{f['points']:>2}] {f['file']}:{f['line']}  {f['why']}")
    fail = args.fail_on if args.fail_on is not None else rep["fail_on"]
    return 1 if fail is not None and rep["score"] >= fail else 0


if __name__ == "__main__":
    sys.exit(main())
