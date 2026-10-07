"""Golden diff-bomb tests. Plain asserts; run `python tests/test_ghostcommit.py` (pytest also works)."""
import json
import subprocess
import sys
import tempfile
import traceback
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "skills" / "ghostcommit" / "scripts"))
import audit  # noqa: E402

GIT = ["git", "-c", "user.name=t", "-c", "user.email=t@t", "-c", "commit.gpgsign=false"]
FAKE_KEY = "sk-" + "abcdefghijklmnopqrstuvwxyz123456"  # built at runtime so this file itself is clean


class Repo:
    def __init__(self, files=None, branch="main"):
        self._tmp = tempfile.TemporaryDirectory()
        self.path = Path(self._tmp.name)
        self.git("init", "-q", "-b", branch)
        if files:
            self.write(files)
            self.git("add", "-A")
            self.git("commit", "-q", "-m", "base")

    def git(self, *a):
        subprocess.run([*GIT, "-C", str(self.path), *a], check=True, capture_output=True)

    def write(self, files):
        for p, t in files.items():
            f = self.path / p
            f.parent.mkdir(parents=True, exist_ok=True)
            f.write_text(t, "utf-8")

    def stage(self):
        self.git("add", "-A")

    def audit(self, **kw):
        return audit.run(self.path, **kw)


def kinds(rep):
    return {f["kind"] for f in rep["findings"]}


FETCH_OK = "def fetch(url):\n    try:\n        return get(url)\n    except Exception as e:\n        log(e)\n        return None\n"


def test_lost_try_except():
    r = Repo({"api.py": FETCH_OK})
    r.write({"api.py": "def fetch(url):\n    return get(url)\n"})
    r.stage()
    rep = r.audit()
    assert "lost_error_handling" in kinds(rep), rep["findings"]
    assert rep["band"] == "yellow" and rep["mode"] == "staged"


def test_swallowed_error():
    r = Repo({"a.py": "def f():\n    return 1\n"})
    r.write({"a.py": "def f():\n    try:\n        return risky()\n    except Exception:\n        pass\n"})
    assert "swallowed_error" in kinds(r.audit())


def test_placeholder_truncation():
    r = Repo({"a.py": "def f():\n    return 1\n\ndef g():\n    return 2\n"})
    r.write({"a.py": "def f():\n    return 1\n\n# ... existing code ...\n"})
    rep = r.audit()
    assert "placeholder" in kinds(rep) and "deleted_function" in kinds(rep)


def test_phantom_import():
    r = Repo({"a.py": "import os\n"})
    r.write({"a.py": "import os\nimport json\nimport totally_made_up_pkg_xyz\ntry:\n    import another_fake_opt_dep\nexcept ImportError:\n    pass\n"})
    why = [f["why"] for f in r.audit()["findings"] if f["kind"] == "phantom_import"]
    assert len(why) == 1 and "totally_made_up_pkg_xyz" in why[0], why


def test_tests_weakened():
    base = "def test_a():\n    assert f(1) == 1\n    assert f(2) == 2\n"
    r = Repo({"tests/test_a.py": base})
    r.write({"tests/test_a.py": "import pytest\n\n@pytest.mark.skip\ndef test_a():\n    pass\n"})
    k = kinds(r.audit())
    assert {"removed_assertions", "skipped_tests"} <= k, k


def test_secret_redacted_everywhere():
    r = Repo({"a.py": "x = 1\n"})
    r.write({"a.py": f'x = 1\nAPI_KEY = "{FAKE_KEY}"\n'})
    rep = r.audit()
    assert "secret" in kinds(rep)
    assert FAKE_KEY not in json.dumps(rep), "secret leaked into report"


def test_clean_diff_is_green():
    r = Repo({"util.py": "def add(a: int, b: int) -> int:\n    return a + b\n"})
    r.write({"util.py": "def add(a: int, b: int) -> int:\n    return a + b\n\n\ndef sub(a: int, b: int) -> int:\n    return a - b\n"})
    rep = r.audit(task="add sub helper")
    assert rep["band"] == "green" and rep["score"] < 30 and not rep["findings"], rep["findings"]


def test_unstaged_and_untracked_are_seen():
    r = Repo({"a.py": "x = 1\n"})
    r.write({"a.py": "x = 2\n", "new_helper.py": f'TOKEN = "{FAKE_KEY}"\n'})
    rep = r.audit()
    assert rep["mode"] == "worktree"
    assert {f["path"] for f in rep["files"]} == {"a.py", "new_helper.py"}
    assert "secret" in kinds(rep)


def test_staged_takes_precedence():
    r = Repo({"a.py": "x = 1\n", "b.py": "y = 1\n"})
    r.write({"a.py": "x = 2\n"})
    r.stage()
    r.write({"b.py": "y = 2\n"})
    assert {f["path"] for f in r.audit()["files"]} == {"a.py"}


def test_gutted_signature_syntax():
    big = "def work(a):\n    x = a + 1\n    y = x * 2\n    z = y - 3\n    return z\n"
    r = Repo({"a.py": big, "b.py": "x = 1\n"})
    r.write({"a.py": "def work(a, b):\n    pass\n", "b.py": "def (:\n"})
    k = kinds(r.audit())
    assert {"gutted_body", "signature_changed", "syntax_error"} <= k, k


def test_removed_guard_and_function():
    old = "def f(x):\n    if x is None:\n        return 0\n    return x + 1\n\ndef g():\n    return 1\n"
    r = Repo({"a.py": old})
    r.write({"a.py": "def f(x):\n    return x + 1\n"})
    k = kinds(r.audit())
    assert {"removed_guard", "deleted_function"} <= k, k


def test_suppression_marker():
    r = Repo({"a.py": "x = 1\n"})
    r.write({"a.py": "x = 1\nimport not_a_real_pkg_zzz  # ghostcommit: ok\n"})
    assert "phantom_import" not in kinds(r.audit())


def test_js_checks():
    r = Repo({
        "package.json": json.dumps({"dependencies": {"express": "1"}}),
        "svc.js": "async function load(u) {\n  try {\n    return await fetch(u);\n  } catch (e) {\n    throw e;\n  }\n}\n",
    })
    r.write({"svc.js": "import express from 'express';\nimport fs from 'fs';\nimport ghost from 'left-pad-ghost';\nimport x from './x';\nasync function load(u) {\n  return await fetch(u);\n}\n"})
    rep = r.audit()
    ph = [f["why"] for f in rep["findings"] if f["kind"] == "phantom_import"]
    assert len(ph) == 1 and "left-pad-ghost" in ph[0], ph
    assert "lost_error_handling" in kinds(rep)


def test_bomb_is_red():
    r = Repo({"api.py": FETCH_OK})
    r.write({"api.py": f'def fetch(url):\n    KEY = "{FAKE_KEY}"\n    try:\n        return get(url)\n    except Exception:\n        pass\n'})
    rep = r.audit()
    assert rep["band"] == "red" and rep["score"] >= 60, (rep["score"], rep["findings"])


def test_config_ignore_and_threshold():
    r = Repo({"a.py": "x = 1\n", "gen/out.py": "y = 1\n", ".ghostcommit.toml": '[thresholds]\nyellow = 1\nred = 2\n'})
    r.write({"a.py": "x = 2\n", "gen/out.py": f'T = "{FAKE_KEY}"\n', ".ghostcommit.toml": 'ignore = ["gen/*"]\n[thresholds]\nyellow = 1\nred = 2\n'})
    rep = r.audit()
    assert "gen/out.py" not in {f["path"] for f in rep["files"]}
    assert rep["band"] == "red"  # tampered config file itself is flagged (6 pts >= red=2)


def test_task_sources():
    r = Repo({"a.py": "x = 1\n"}, branch="main")
    r.git("checkout", "-q", "-b", "feat/add-retry-logic")
    r.write({"a.py": "x = 2\n"})
    rep = r.audit()
    assert rep["task"] == "add retry logic" and rep["task_source"] == "branch", rep["task"]
    rep = r.audit(task="explicit")
    assert rep["task"] == "explicit" and rep["task_source"] == "flag"


def test_off_spec_hint():
    r = Repo({"fetch.py": "def fetch():\n    return 1\n", "billing.py": "def charge():\n    return 1\n"})
    r.write({"fetch.py": "def fetch():\n    return 2\n", "billing.py": "def charge():\n    return 2\n"})
    flagged = {f["file"] for f in r.audit(task="add retry logic to fetch")["findings"] if f["kind"] == "off_spec_hint"}
    assert flagged == {"billing.py"}, flagged


def test_no_head_initial_commit():
    r = Repo()
    r.write({"a.py": "import fake_pkg_for_test\n"})
    r.stage()
    assert "phantom_import" in kinds(r.audit())


def test_base_mode():
    r = Repo({"a.py": FETCH_OK})
    r.git("checkout", "-q", "-b", "agent")
    r.write({"a.py": "def fetch(url):\n    return get(url)\n"})
    r.stage()
    r.git("commit", "-q", "-m", "agent change")
    rep = r.audit(base="main")
    assert rep["mode"] == "base" and "lost_error_handling" in kinds(rep)


def test_sarif_and_cli_exit_code():
    r = Repo({"a.py": "x = 1\n"})
    r.write({"a.py": f'x = 1\nK = "{FAKE_KEY}"\n'})
    r.stage()
    out = r.path / "o.sarif"
    code = audit.main(["--repo", str(r.path), "--fail-on", "10", "--sarif", str(out)])
    assert code == 1
    s = json.loads(out.read_text("utf-8"))
    assert s["version"] == "2.1.0" and s["runs"][0]["results"][0]["ruleId"] == "secret"
    assert len(audit.run(r.path)["summary"]) == 3


def test_empty_diff():
    r = Repo({"a.py": "x = 1\n"})
    rep = r.audit()
    assert rep["score"] == 0 and rep["stats"]["files"] == 0 and rep["band"] == "green"


def test_configured_weight_is_not_clamped():
    r = Repo({"a.py": "x = 1\n", ".ghostcommit.toml": "[weights]\nsecret = 70\n"})
    r.write({"a.py": f'x = 1\nK = "{FAKE_KEY}"\n'})
    rep = r.audit()
    assert rep["score"] == 70 and rep["band"] == "red", (rep["score"], rep["breakdown"])


def test_weak_signals_alone_never_red():
    r = Repo({**{f"m{i}.py": "x = 1\n" for i in range(8)}, "fetch.py": "x = 1\n"})
    r.write({**{f"m{i}.py": "x = 123456\n" for i in range(8)}, "fetch.py": "x = 2\n", "Dockerfile": "FROM x\n", "package.json": "{}"})
    rep = r.audit(task="add retry logic to fetch")
    assert {"off_spec_hint", "magic_value", "quiet_risk"} <= kinds(rep), kinds(rep)
    assert rep["score"] == 35 and rep["band"] == "yellow", (rep["score"], rep["breakdown"])


def test_pep723_declared_deps_are_not_phantom():
    r = Repo({"x.py": "x = 1\n"})
    r.write({"x.py": '# /// script\n# dependencies = ["somefancylib>=1"]\n# ///\nimport somefancylib\nimport undeclaredfancylib\n'})
    why = [f["why"] for f in r.audit()["findings"] if f["kind"] == "phantom_import"]
    assert len(why) == 1 and "undeclaredfancylib" in why[0], why


def test_markdown_is_not_muzzled_tooling():
    r = Repo({"README.md": "hi\n"})
    r.write({"README.md": "hi\nuse `# type: ignore` sparingly\n"})
    assert "muzzled_tooling" not in kinds(r.audit())


def ts_available():
    return audit.symbols_ts is not None and audit.symbols_ts.analyze(".ts", "function f() {}") is not None


TS_OLD = """export async function load(u: string, n: number): Promise<string> {
  if (!u) { throw new Error('url required'); }
  try { return await fetchIt(u, n); } catch (e) { log(e); return ''; }
}
export function other(a: number): number { return a + 1; }
class Svc {
  run(x: number): number { return x; }
}
"""
TS_NEW = """export async function load(u, n) {
  try { return await fetchIt(u, n); } catch (e) { }
}
class Svc {
  run(x: number): number { return x; }
}
"""


def test_tree_sitter_ts_symbol_diff():
    if not ts_available():
        print("      (skipped: tree-sitter not installed)")
        return
    r = Repo({"svc.ts": TS_OLD})
    r.write({"svc.ts": TS_NEW})
    rep = r.audit()
    assert {"swallowed_error", "removed_guard", "dropped_types", "deleted_function"} <= kinds(rep), kinds(rep)
    sym = rep["symbols"]["svc.ts"]
    assert "other" in sym["removed"] and "load" in sym["changed"] and "Svc.run" not in sym["changed"], sym


def test_tree_sitter_go_guard_removed():
    if not ts_available():
        print("      (skipped: tree-sitter not installed)")
        return
    old = "package x\n\nfunc (c *Client) Get(u string) (string, error) {\n\ts, err := fetch(u)\n\tif err != nil {\n\t\treturn \"\", err\n\t}\n\treturn s, nil\n}\n"
    new = "package x\n\nfunc (c *Client) Get(u string) (string, error) {\n\ts, _ := fetch(u)\n\treturn s, nil\n}\n"
    r = Repo({"c.go": old})
    r.write({"c.go": new})
    rep = r.audit()
    assert "removed_guard" in kinds(rep) and "Client.Get" in rep["symbols"]["c.go"]["changed"], rep["findings"]


def test_regex_fallback_without_tree_sitter():
    saved, audit.symbols_ts = audit.symbols_ts, None
    try:
        r = Repo({"svc.js": "async function load(u) {\n  try {\n    return await f(u);\n  } catch (e) {\n    throw e;\n  }\n}\n"})
        r.write({"svc.js": "async function load(u) {\n  return await f(u);\n}\n"})
        assert "lost_error_handling" in kinds(r.audit())
    finally:
        audit.symbols_ts = saved


HOOK = Path(__file__).resolve().parent.parent / "hooks" / "capture_intent.py"


def run_hook(cwd, **payload):
    p = subprocess.run([sys.executable, str(HOOK)], input=json.dumps({"cwd": str(cwd), **payload}), capture_output=True, text=True)
    assert p.returncode == 0 and p.stdout == "", p  # must be silent: stdout would be injected into Claude's context


def test_intent_hook():
    r = Repo({"a.py": "x = 1\n"})
    run_hook(r.path, prompt="yes")
    assert r.audit()["task_source"] == "none"
    run_hook(r.path, prompt="Add retry logic with exponential backoff to the fetch helper in api.py please")
    rep = r.audit()
    assert rep["task_source"] == "hook" and "retry" in rep["task"]
    run_hook(r.path, prompt="continue")
    run_hook(r.path, prompt="this long prompt was generated automatically by the harness not typed", auto_continuation=True)
    assert r.audit()["task"] == rep["task"]
    run_hook(r.path, prompt='Use password = "hunter2hunter2" when calling the fetch helper in api.py now please')
    assert "hunter2hunter2" not in json.dumps(r.audit())
    with tempfile.TemporaryDirectory() as d:  # not a git repo: stay silent, do nothing
        run_hook(d, prompt="Add retry logic with exponential backoff to the fetch helper in api.py please")


if __name__ == "__main__":
    failed = 0
    for name, fn in list(globals().items()):
        if name.startswith("test_") and callable(fn):
            try:
                fn()
                print(f"ok    {name}")
            except Exception:  # noqa: BLE001
                failed += 1
                print(f"FAIL  {name}")
                traceback.print_exc()
    sys.exit(1 if failed else 0)
