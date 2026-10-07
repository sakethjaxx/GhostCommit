"""CLI + LLM tests against a mock OpenAI-compatible server. Needs typer, rich, openai (else skips)."""
import json
import subprocess
import sys
import threading
import traceback
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
SCRIPTS = Path(__file__).resolve().parent.parent / "skills" / "ghostcommit" / "scripts"
sys.path.insert(0, str(SCRIPTS))
try:
    import ghostcommit
    from typer.testing import CliRunner
except ImportError as e:
    print(f"SKIP: {e}")
    sys.exit(0)
from test_ghostcommit import FAKE_KEY, FETCH_OK, Repo  # noqa: E402

runner = CliRunner()


class Mock(ThreadingHTTPServer):
    def __init__(self, reject_schema=False):
        super().__init__(("127.0.0.1", 0), Handler)
        self.reject_schema, self.bodies = reject_schema, []
        threading.Thread(target=self.serve_forever, daemon=True).start()

    @property
    def url(self):
        return f"http://127.0.0.1:{self.server_address[1]}/v1"


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def do_POST(self):
        body = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
        self.server.bodies.append(body)
        if self.server.reject_schema and body["response_format"]["type"] == "json_schema":
            data, code = {"error": {"message": "json_schema unsupported", "type": "invalid_request_error"}}, 400
        else:
            prompt = body["messages"][-1]["content"]
            if "FILE: billing.py" in prompt:
                ans = {"relevant": False, "reason": "billing is unrelated to retry", "regressions": []}
            else:
                ans = {"relevant": True, "reason": "ok", "regressions": [{"line": 2, "reason": "drops validation"}]}
            data, code = {"id": "x", "object": "chat.completion", "created": 0, "model": "m",
                          "choices": [{"index": 0, "finish_reason": "stop", "message": {"role": "assistant", "content": json.dumps(ans)}}]}, 200
        raw = json.dumps(data).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)


def two_file_repo():
    r = Repo({"fetch.py": "def fetch():\n    return 1\n", "billing.py": "def charge():\n    return 1\n"})
    r.write({"fetch.py": f"def fetch():\n    return 2  # {FAKE_KEY}\n", "billing.py": "def charge():\n    return 2\n"})
    return r


def invoke(r, *args):
    return runner.invoke(ghostcommit.app, ["--repo", str(r.path), *args])


def test_three_lines_and_exit_code():
    r = two_file_repo()
    res = invoke(r, "--no-llm", "--task", "add retry to fetch")
    lines = [l for l in res.output.splitlines() if l.strip()]
    assert len(lines) == 3 and lines[0].startswith("RISK"), res.output
    assert invoke(r, "--no-llm", "--fail-on", "10").exit_code == 1
    assert invoke(r, "--no-llm", "--fail-on", "99").exit_code == 0


def test_llm_adds_findings_and_never_leaks_secret():
    srv = Mock()
    r = two_file_repo()
    res = invoke(r, "--base-url", srv.url, "--model", "m", "--task", "add retry to fetch", "--json")
    rep = json.loads(res.output)
    k = {f["kind"] for f in rep["findings"]}
    assert {"llm_off_spec", "llm_regression", "secret"} <= k, k
    assert rep["intent_match"] == 50
    assert srv.bodies and all(FAKE_KEY not in json.dumps(b) for b in srv.bodies), "secret sent to LLM"
    assert "LLM:" in "".join(f["why"] for f in rep["findings"])
    srv.shutdown()


def test_schema_rejected_falls_back_to_json_object():
    srv = Mock(reject_schema=True)
    r = two_file_repo()
    rep = json.loads(invoke(r, "--base-url", srv.url, "--model", "m", "--task", "add retry to fetch", "--json").output)
    assert any(f["kind"] == "llm_off_spec" for f in rep["findings"])
    assert {b["response_format"]["type"] for b in srv.bodies} == {"json_schema", "json_object"}
    srv.shutdown()


def test_llm_down_degrades_to_heuristics():
    r = two_file_repo()
    res = invoke(r, "--base-url", "http://127.0.0.1:9/v1", "--model", "m")
    assert res.exit_code == 0 and "RISK" in res.output and "LLM unavailable" in res.output, res.output


def test_remote_provider_needs_key():
    import os

    os.environ.pop("GROQ_API_KEY", None)
    os.environ.pop("GHOSTCOMMIT_API_KEY", None)
    res = invoke(two_file_repo(), "--provider", "groq")
    assert "needs a key" in res.output and res.exit_code == 0, res.output


def test_hook_blocks_bad_commit_and_allows_clean():
    r = Repo({"api.py": FETCH_OK})
    res = runner.invoke(ghostcommit.app, ["hook", "install", "--repo", str(r.path)])
    assert res.exit_code == 0 and (r.path / ".git" / "hooks" / "pre-commit").exists(), res.output
    r.write({"api.py": f'def fetch(url):\n    KEY = "{FAKE_KEY}"\n    try:\n        return get(url)\n    except Exception:\n        pass\n'})
    r.stage()
    git = ["git", "-c", "user.name=t", "-c", "user.email=t@t", "-C", str(r.path)]
    bad = subprocess.run([*git, "commit", "-q", "-m", "bomb"], capture_output=True, text=True)
    assert bad.returncode != 0 and "ghostcommit" in (bad.stderr + bad.stdout).lower(), bad
    r.write({"api.py": FETCH_OK + "\n\ndef other():\n    return 1\n"})
    r.stage()
    ok = subprocess.run([*git, "commit", "-q", "-m", "fine"], capture_output=True, text=True)
    assert ok.returncode == 0, ok.stderr + ok.stdout
    assert "removed" in runner.invoke(ghostcommit.app, ["hook", "uninstall", "--repo", str(r.path)]).output


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
