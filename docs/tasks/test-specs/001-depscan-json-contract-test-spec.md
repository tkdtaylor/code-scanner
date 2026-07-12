# Test Spec — Task 001: Consume dep-scan via the documented `--format json` contract

All tests live in `tests/test_gate_cli.py` and run hermetically (no network, no Docker) unless marked otherwise: `python3 -m pytest tests/test_gate_cli.py -v`.

Conventions used below:

- `cs` is the CLI module loaded by the existing `_load_cli_module()` helper (the extensionless `cli/code-scanner` shim).
- "Unit" tests monkeypatch on `cs`: `cs._have = lambda tool: tool == "dep-scan"` and `cs._run = <recording stub>` that appends `cmd` to a list and returns a canned `(rc, stdout, stderr)`.
- "E2E" tests use the existing `run_cli(target, path=...)` subprocess helper with `fake_path()` (only `tests/fake-tools/` on PATH) against the `tests/fixtures/clean-repo` and `tests/fixtures/vulnerable-repo` fixtures.
- For unit tests needing a manifest, create `tmp_path/"requirements.txt"` containing exactly `pyyaml==5.3.1\n`; `_find_dep_manifests` then yields one `("pypi", <path>, True)` entry, so `run_dep_scan` issues exactly one lockfile-mode command.

## Invocation contract

### T-001-01: Static check: deprecated flag is gone, documented flag is present
- Read `cli/code-scanner` and `code-scanner/references/scan-commands.md` as text.
- Expected: the token `--json` appears in **neither** file (word-boundary match, i.e. `--json` not followed by an identifier character, so `--format json` never matches); `cli/code-scanner` contains `"--format", "json"` at least twice (lockfile-mode and name-mode command constructions); `scan-commands.md` contains at least six `dep-scan check` blocks with `--format json`.

### T-001-02: Command shape, lockfile mode (recording stub)
- Arrange: monkeypatched `cs._have`/`cs._run` (stub returns `(0, "[]", "")`), tmp dir with the `requirements.txt` fixture.
- Act: `cs.run_dep_scan(str(tmp_path))`.
- Expected: exactly one recorded command, equal to `["dep-scan", "check", "--lockfile", <abs path to requirements.txt>, "--lockfile-type", "pypi", "--format", "json"]`; return value is `[]`.

### T-001-03: Command shape, name mode
- Arrange: tmp dir containing only `package.json` with `{"dependencies": {"left-pad": "^1.0.0"}}`; same stub returning `(0, "[]", "")`.
- Act: `cs.run_dep_scan(str(tmp_path))`.
- Expected: exactly one recorded command, equal to `["dep-scan", "check", "left-pad", "--registry", "npm", "--format", "json"]`.

### T-001-04: Fake tool rejects a regression to the deprecated flag
- Arrange: run `tests/fake-tools/dep-scan` directly as a subprocess twice:
  1. argv `["check", "--lockfile", "x", "--lockfile-type", "pypi", "--format", "json"]` with cwd inside a path containing `clean`.
  2. argv `["check", "--lockfile", "x", "--lockfile-type", "pypi", "--json"]`.
- Expected: run 1 exits `0` with stdout `[]` (valid JSON). Run 2 exits `2` with **empty stdout** and a non-empty stderr diagnostic naming the deprecated flag. (Empty stdout + rc 2 is what forces `run_dep_scan` into `ToolError`, so the whole suite fails if the CLI ever regresses.)

## Output-shape parsing (pins the documented contract)

### T-001-05: Bare array shape passes through
- `cs._dep_scan_entries([{"package": "a"}, {"package": "b"}])`
- Expected: exactly `[{"package": "a"}, {"package": "b"}]` (same objects, same order).

### T-001-06: Two-key transitive shape unwraps `results`
- `cs._dep_scan_entries({"results": [{"package": "a"}], "transitive": {"worst_verdict": "block", "diagnostics": [], "nodes": []}})`
- Expected: exactly `[{"package": "a"}]`. The `transitive` key is ignored (the gate CLI does not consume transitive verdicts in this task).

### T-001-07: Unknown top-level types yield an empty list
- For each of `"oops"`, `42`, `None`, `{"no_results_key": 1}`: `cs._dep_scan_entries(x)`
- Expected: `[]` for the first three; `[]` for the dict without `results` (via `data.get("results", []) or []`). No exception in any case.

## Finding mapping

### T-001-08: Per-policy mapping with mixed pass/warn/block
- Arrange: stub returns `(1, json.dumps([entry]), "")` where `entry` is:

```json
{
  "package": "PyYAML",
  "version": "5.3.1",
  "registry": "pypi",
  "age_hours": 40000,
  "result": "block",
  "reason": "Found known vulnerability(ies): GHSA-8q59-q68h-6hv4",
  "policies": [
    {"policy_name": "age", "result": "pass", "reason": null},
    {"policy_name": "typosquatting", "result": "warn", "reason": "similar to 'pyaml'"},
    {"policy_name": "vulnerability", "result": "block", "reason": "Found known vulnerability(ies): GHSA-8q59-q68h-6hv4"}
  ]
}
```

- Act: `findings = cs.run_dep_scan(str(tmp_path))` (requirements.txt fixture).
- Expected: exactly **2** findings (the `pass` policy produces none):
  - one with `rule_id == "dep-scan/typosquatting"`, `severity == "MEDIUM"`, `message == "PyYAML@5.3.1: similar to 'pyaml'"`, `driver == "dep-scan"`, `tier == cs.TIER_DETERMINISTIC`;
  - one with `rule_id == "dep-scan/vulnerability"`, `severity == "HIGH"`, message containing `"PyYAML@5.3.1: Found known vulnerability(ies): GHSA-8q59-q68h-6hv4"`.
- Both findings' `path` is the manifest path (relative or absolute per `_rel` semantics; assert it ends with `requirements.txt`).

### T-001-09: Warm-cache sentinel does not gate (baseline for task 002)
- Arrange: stub returns `(1, json.dumps([{"package": "PyYAML", "version": "cached", "registry": "pypi", "age_hours": null, "result": "block", "reason": "cached result", "policies": []}]), "")`.
- Act: `cs.run_dep_scan(str(tmp_path))` with `capsys`.
- Expected: returns `[]` (zero findings); stderr contains `unattributable` and `not gating`. This pins today's fail-closed exclusion verbatim so task 002 changes it deliberately, not accidentally.

## Fail-closed and exit codes

### T-001-10: Unparseable stdout raises ToolError → CLI exit 2
- Unit: stub returns `(1, "not json {", "")`; expect `pytest.raises(cs.ToolError)` with message containing `unparseable JSON`.
- E2E: not required (the ToolError → exit 2 path is already covered by the existing `test_no_deterministic_tools_is_tool_failure` wiring; the unit assertion is the contract).

### T-001-11: rc 2 with empty stdout raises ToolError
- Unit: stub returns `(2, "", "boom: config invalid")`; expect `cs.ToolError` whose message contains `rc=2`.
- Counter-case: stub returns `(1, "[]", "")`; expect `[]` with no exception (rc 1 with parseable output is findings-not-failure).

### T-001-12: End-to-end exit codes preserved (0/1/2/64)
- `run_cli(CLEAN, path=fake_path())` → rc `0`.
- `run_cli(VULN, path=fake_path())` → rc `1`, and the SARIF contains an error-level deterministic result with `ruleId == "dep-scan/vulnerability"` from the fake's block policy.
- `run_cli(CLEAN, path=minimal_path())` → rc `2` (no deterministic tools; unchanged).
- `run_cli(CLEAN, "--severity-threshold", "BOGUS", path=fake_path())` → rc `64`.
- (The first, third, and fourth assertions duplicate existing tests; keep them in this spec as the explicit non-regression gate for the flag switch and assert them in one parametrized test rather than trusting incidental coverage.)

## Regression / mutation checks

### T-001-13: Mutation check: reverting one flag breaks the suite (manual, recorded in the verify commit)
- Manually change one `"--format", "json"` back to `"--json"` in `run_dep_scan`, run the suite.
- Expected: T-001-01 fails (static) **and** T-001-12's vulnerable-fixture case fails with exit 2 (the hardened fake refuses the deprecated flag). Restore the change. Record the observed failure output as L5 evidence that the tests bite.

### T-001-14: Existing suite green
- The full pre-existing test file passes unchanged aside from tests explicitly modified by this task.
- Expected: `python3 -m pytest tests/test_gate_cli.py -v` → 0 failures.
