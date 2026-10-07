# GhostCommit

**Adversarial safety net for AI diff-bombs.** AI coding tools touch files you never asked about, silently delete `try/except`, drop type hints, import packages that do not exist, and leave `# ... existing code ...` in your source. GhostCommit audits your changes against the task, then prints a 3-line summary and a color-coded **Diff Risk Score**.

```
RISK 100/100 RED | 3 files +12/-11 | task: add retry logic to fetch
Top: truncation placeholder in code (LLM elided content) (api/fetch.py:7) +10 more
STOP: review the flagged items line-by-line before committing.
```

Report only. It never edits, stages or reverts anything.

## What it catches

| Signal | Examples |
|---|---|
| Off-spec mutations | files/helpers unrelated to the task (weak hint from the script; the LLM or your agent decides) |
| Silent regressions | deleted try/catch and `err != nil` checks, removed guard clauses and `raise`/`assert`, swallowed exceptions, gutted function bodies, changed signatures, deleted functions, dropped types and comments |
| Hallucination tells | imports that resolve to nothing, truncation placeholders (`... existing code ...`), stub bodies |
| Trust erosion | skipped/removed tests, `# type: ignore` / `eslint-disable`, hardcoded secrets and magic values, lockfile/CI/config edits, reformat noise that buries real edits |

Python gets an exact AST diff per function (stdlib `ast`). JS/TS/Go get the same via tree-sitter when installed, otherwise line regexes. Details and weights: `KINDS` in [audit.py](skills/ghostcommit/scripts/audit.py).

**Scoring.** Points add up to 100. GREEN < 30, YELLOW 30-59, RED >= 60. Weak signals (off-spec hints, magic values, config edits, LLM opinions) together add at most 35, so **RED always needs a strong signal**. The LLM can only add findings, never lower the score, so a prompt-injected diff cannot talk its way to green.

## Install

Pick one. All three ship the same skill.

**skills.sh (works with Claude Code, Codex, Cursor, Copilot, ...)**
```bash
npx skills add sakethjaxx/GhostCommit
```
skills.sh ranks skills by install activity; there is no separate submit step that I could confirm, so the listing appears once people install it.

**Claude Code plugin** (adds the intent-capture hook)
```
/plugin marketplace add sakethjaxx/GhostCommit
/plugin install ghostcommit@ghostcommit
```

**ChatGPT / Codex plugin.** Open this repo as a local marketplace (`.agents/plugins/marketplace.json`) in the Plugins Directory. The manifest is the root `plugin.json` (Agent Plugins schema + `extensions.com.openai`). Plain ChatGPT chat cannot run scripts: the skill then asks you to paste `git diff` and applies its rubric by hand.

## Use it

**Inside an agent.** Say "audit my changes" (or "review my staged diff before I commit"). The skill runs the stdlib-only `audit.py` and your agent judges the diff using `references/rubric.md`. No API key needed.

**CLI** (typer + rich, own LLM pass):
```bash
pip install typer rich openai          # or: uv run skills/ghostcommit/scripts/ghostcommit.py
python skills/ghostcommit/scripts/ghostcommit.py --task "add retry to fetch" -v
python skills/ghostcommit/scripts/ghostcommit.py --no-llm          # deterministic checks only
python skills/ghostcommit/scripts/ghostcommit.py --base origin/main # audit a whole branch
```
Scope is the staged diff; if nothing is staged, the working tree plus untracked files (agents rarely stage).

**Pre-commit gate**
```bash
python skills/ghostcommit/scripts/ghostcommit.py hook install --fail-on 60   # add --llm to also call the model
python skills/ghostcommit/scripts/ghostcommit.py hook uninstall
```

**CI / pull requests** (adds SARIF for code scanning):
```yaml
- uses: actions/checkout@v4
  with: { fetch-depth: 0 }
- uses: sakethjaxx/GhostCommit@v0.1.0
  with: { fail-on: "60", upload-sarif: "false" }   # "true" needs code scanning + security-events: write
```

## Where the task comes from

First hit wins: `--task` > `GHOSTCOMMIT_TASK` > the last prompt captured by the Claude Code hook (`.git/ghostcommit/task`, local only, secrets redacted, ignored after 24 h) > the branch name (`feat/add-retry-logic` becomes "add retry logic"). Short prompts ("yes", "continue") never overwrite the captured task.

## LLM backends (open models)

One OpenAI-compatible client, strict JSON-schema output with a `json_object` fallback. If the model is down or answers garbage, you still get the heuristic report; a commit is never blocked by an LLM outage.

| `--provider` | Default model | Needs |
|---|---|---|
| `ollama` (default) | `qwen2.5-coder:7b` | local [Ollama](https://ollama.com), no key |
| `groq` | `openai/gpt-oss-20b` | `GROQ_API_KEY` |
| `openrouter` | `openai/gpt-oss-20b` | `OPENROUTER_API_KEY` |
| any | `--base-url` + `--model` | `GHOSTCOMMIT_API_KEY` if remote |

Override with `--model`, `--base-url`, `--timeout`, `--max-files` or env `GHOSTCOMMIT_PROVIDER/MODEL/BASE_URL/API_KEY/TIMEOUT`.

- **Speed and quality depend on your hardware.** A 3B-7B model on CPU takes tens of seconds per file and a 3B model hallucinated findings in my smoke test. Prefer a 7B+ coder model, a GPU, or a hosted open model such as Groq. That is why LLM findings are weighted low.
- **Privacy.** Local endpoints send nothing off your machine. Remote endpoints receive a **secret-redacted** diff and the CLI says so. Redaction is pattern-based, not a guarantee.

## Configure

`.ghostcommit.toml` in the repo root:
```toml
fail_on = 60
ignore = ["vendor/*", "*.generated.ts"]
[thresholds]
yellow = 30
red = 60
weak_cap = 35
[weights]            # points per hit for any finding kind
secret = 60
[llm]
provider = "groq"
model = "openai/gpt-oss-20b"
```
Suppress a line with a comment containing `ghostcommit: ok`. Editing `.ghostcommit.toml` is itself flagged, so the gate cannot be loosened silently.

## Known limits

- Regex checks are line-level outside Python/tree-sitter languages; they will have false positives (moved code, optional imports). Findings are leads, and the skill tells your agent to confirm or dismiss each.
- Phantom-import detection can only see the interpreter running the audit plus declared dependencies; run it from your project's environment.
- Off-spec detection is vocabulary overlap plus LLM judgment. There is no cross-file caller graph yet.
- The Codex hook is not provided (Codex only allows hooks for manually installed plugins); the intent-capture hook is Claude Code only.
- I could not test installation inside ChatGPT or Codex from here; the manifests follow OpenAI's published schema.

## Develop

```bash
python tests/test_ghostcommit.py     # stdlib only: golden diff-bomb fixtures in temp git repos
python tests/test_cli.py             # needs typer rich openai; uses a mock OpenAI-compatible server
claude plugin validate .
npx skills add . --list
```

MIT licensed.
