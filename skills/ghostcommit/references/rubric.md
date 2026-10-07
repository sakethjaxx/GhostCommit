# Semantic audit rubric

Use with the JSON from `audit.py`. Goal: catch what an AI coding tool slipped into a large diff.

## 1. Off-spec mutations
For every changed file and symbol ask: *would the task still be complete without this change?*
- Unrelated files touched (a billing change in a "retry logic" task).
- Helpers or shared utilities modified "while passing through", especially ones with many callers.
- Renames, reformatting, reordering, dependency bumps, or config edits nobody asked for.
- New abstractions, wrappers, or files the task did not need.
Mark a file **off-spec** only after reading its diff. The script's `off_spec_hint` is just vocabulary overlap.

## 2. Silent regressions (look at removed `-` lines first)
- Deleted try/catch, `finally`, `err != nil` checks; handler replaced by `pass`, `return None`, or log-only.
- Removed guard clauses (null/empty checks, early returns, bounds, auth/permission checks, input validation).
- Removed `raise`/`throw`/`assert` so failures now pass silently.
- Retry/timeout/limit values changed, loops made unbounded, or constants inlined.
- Dropped type annotations, docstrings, or explanatory comments (especially "why" comments).
- Behaviour narrowed: a branch, `else`, or edge case (empty list, zero, unicode, timezone) no longer handled.
- Changed return shape, default argument, or signature while callers elsewhere are untouched.

## 3. Hallucination tells
- Imports of packages not declared or installed; calls to functions, methods, flags, or config keys that exist nowhere in the repo.
- Placeholder text left in code: `... existing code ...`, "rest unchanged", `pass`/`NotImplementedError` bodies, TODO stubs.
- A function that now looks right but whose body shrank sharply.

## 4. Trust erosion
- Tests deleted, skipped, `.only`'d, or assertions weakened so the suite still goes green.
- `# type: ignore`, `noqa`, `eslint-disable`, `@ts-ignore` added to silence a real problem.
- Hardcoded secrets, URLs, magic numbers; lockfile, CI, Dockerfile, or `.env` edits that the task does not explain.

## Judging a finding
- **Confirm** when the diff shows the behaviour is gone or weaker and nothing replaced it.
- **Dismiss** when code was moved/extracted (the handler now lives elsewhere in the diff), the import is an optional/guarded one, or the line is intentionally marked.
- **Escalate** when several small signals sit in the same function or file.

## Output discipline
Cite `file:line`. Say what changed and why it matters in one sentence. No rewrites, no patches: report only.
