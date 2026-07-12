# Task 001 — Consume dep-scan via the documented `--format json` contract

**Status:** backlog
**Depends on:** none (pure consumer-side; requires no dep-scan changes)
**Test spec:** [`../test-specs/001-depscan-json-contract-test-spec.md`](../test-specs/001-depscan-json-contract-test-spec.md)

## Objective

Switch every dep-scan invocation in this repo from the deprecated `--json` flag to the documented stable contract `dep-scan check ... --format json`, and pin the parsing of that contract with regression tests: per-policy results map into the existing SARIF runs and gating tiers exactly as today, exit-code semantics (0/1/2/64) are preserved, and the fail-closed rules are unchanged.

## Context

The headless gate CLI (`cli/code-scanner`, delivered as Phase 5 of `plans/PLAN-v1.md` via `plans/TASK-001-headless-cli-gate-mode.md`) runs dep-scan as one of three deterministic-tier tools (ADR-001 reliability tiers; ADR-002 native-tools execution model). Only the deterministic tier gates the build.

**Repo fact that reframes this task:** the CLI does *not* parse dep-scan's native text output. `run_dep_scan` already requests JSON, but via the `--json` flag. dep-scan's spec (`dep-scan/docs/spec/interfaces.md`) documents `--json` as a **deprecated, hidden alias** for `--format json` ("Kept for backward compatibility; use `--format json` instead"), meaning it can disappear on a dep-scan major version bump. `--format json` is the documented surface with a stability guarantee ("JSON top-level shape: Stable; additive only"; per-policy `result` values exactly `pass` / `warn` / `block`). The change here is deprecated-alias → documented-contract, plus tests that pin the schema we depend on. In dep-scan, `resolve_format` maps `--json` to the same `OutputFormat::Json`, so the emitted bytes are identical; behavior must therefore be observably unchanged.

The conversational skill documents the same deprecated flag: `code-scanner/references/scan-commands.md` has six `dep-scan check ... --json` command blocks (lines 243, 249, 260, 272, 281, 288 at time of writing) plus prose at line 299 ("dep-scan emits JSON when `--json` is used"). The skill executes these blocks verbatim, so they are part of the same consumer-side contract and are updated in this task.

## Files and functions (exact)

| File | What changes |
|---|---|
| `cli/code-scanner` | `run_dep_scan(target)` (the two `cmd = [...]` constructions, currently ending in `"--json"`) and its docstring. `_dep_scan_entries(data)`, `_REGISTRY`, `_LOCKFILE_TYPE` are *referenced* by tests but unchanged. |
| `tests/fake-tools/dep-scan` | Hermetic fake hardened to reject the deprecated flag (see step 2). |
| `tests/test_gate_cli.py` | New tests per the test spec (T-001-01 … T-001-12). |
| `code-scanner/references/scan-commands.md` | All `--json` occurrences in dep-scan commands → `--format json`; prose at line 299 updated. |

## Exact command shapes (before → after)

Lockfile mode (version-bearing manifests: `package-lock.json`, `requirements*.txt`, `Cargo.lock`, `go.sum`):

```
before: ["dep-scan", "check", "--lockfile", <path>, "--lockfile-type", <npm|pypi|crates|go>, "--json"]
after:  ["dep-scan", "check", "--lockfile", <path>, "--lockfile-type", <npm|pypi|crates|go>, "--format", "json"]
```

Name mode (`package.json` without a lock, `pyproject.toml`):

```
before: ["dep-scan", "check", <name>..., "--registry", <npm|pypi|crates-io|go>, "--json"]
after:  ["dep-scan", "check", <name>..., "--registry", <npm|pypi|crates-io|go>, "--format", "json"]
```

## Parsed output shapes (unchanged, now pinned by tests)

`--format json` emits one of two shapes on stdout (identical to what `--json` emitted; both already handled by `_dep_scan_entries`):

1. **Transitive disabled (our case; the gate CLI never passes `--transitive`):** a bare JSON array of per-package entries.
2. **Transitive enabled:** a two-key object `{"results": [<entries>], "transitive": {...}}`. `_dep_scan_entries` returns `data.get("results", [])` for this shape; keep it so a future `--transitive` adoption or a dep-scan config file enabling transitive does not break parsing.

Each entry is dep-scan's `CheckResult` serialization (`dep-scan/src/main.rs`):

```json
{
  "package": "PyYAML",
  "version": "5.3.1",
  "registry": "pypi",
  "age_hours": 12345,
  "result": "block",
  "reason": "Found known vulnerability(ies): GHSA-8q59-q68h-6hv4",
  "policies": [
    {"policy_name": "age", "result": "pass", "reason": null},
    {"policy_name": "vulnerability", "result": "block", "reason": "Found known vulnerability(ies): GHSA-8q59-q68h-6hv4"}
  ]
}
```

Keep the existing `entry.get("package") or entry.get("name", "?")` accessor (dep-scan's spec example uses `name`; its code emits `package`; tolerate both).

## Finding mapping (unchanged, now pinned by tests)

- Only entries with at least one policy whose `result` is `block` or `warn` produce findings ("attributable policy violations").
- Per violating policy: `rule_id = f"dep-scan/{policy_name}"`, severity `block → HIGH`, `warn → MEDIUM`, `message = f"{name}@{version}: {reason}"` (plus `" (transitive, depth N)"` when `depth` is present), `driver = "dep-scan"`, `tier = TIER_DETERMINISTIC`, `path` = the manifest path relativized via `_rel`.
- An entry whose top-level `result` is `block`/`warn` but whose `policies` list yields no violations (dep-scan's warm-cache sentinel: `version == "cached"`, `policies == []`) does **not** gate; the CLI prints the existing "unattributable … not gating" note to stderr. This exclusion stays exactly as-is in this task (task 002 revisits it once dep-scan task 112 lands).

## Exit-code semantics (must be byte-for-byte preserved)

- code-scanner: `0` clean, `1` gating findings, `2` tool failure / zero deterministic tools, `64` usage (TASK-001 REQ-002).
- dep-scan child process: `0` all pass, `1` warn/block verdicts, `2` runtime error (its documented CI contract). `run_dep_scan` treats `rc in (0, 1)` as normal; any other rc **with empty stdout** raises `ToolError` (→ exit 2, fail closed); non-zero rc with parseable JSON on stdout is findings, not failure; unparseable stdout raises `ToolError`.

## Step-by-step outline

1. In `cli/code-scanner` `run_dep_scan`, replace the trailing `"--json"` element with the two elements `"--format", "json"` in both command constructions. Update the docstring's flag mention.
2. Harden `tests/fake-tools/dep-scan`: before emitting output, inspect `sys.argv`; if `--json` is present, or the adjacent pair `--format json` is absent, print a diagnostic to stderr and exit `2` with **empty stdout** (this drives `run_dep_scan`'s ToolError path, so any regression to the deprecated flag fails the hermetic suite loudly rather than silently passing).
3. Update `code-scanner/references/scan-commands.md`: all six `--json` command occurrences → `--format json`; rewrite the "dep-scan emits JSON when `--json` is used" prose to name `--format json`.
4. Add the tests from the test spec to `tests/test_gate_cli.py` (unit tests monkeypatch `cs._have` / `cs._run` on the already-imported `cs` module; see spec for exact fixtures and assertions).
5. Run `python3 -m pytest tests/test_gate_cli.py -v` (hermetic; no network, no Docker).
6. Static check: `grep -n -- '--json' cli/code-scanner code-scanner/references/scan-commands.md` returns nothing.

## Acceptance criteria

- [ ] Both `run_dep_scan` command constructions use `--format json`; the literal `--json` is absent from `cli/code-scanner` (T-001-01).
- [ ] The hermetic fake rejects `--json` / missing `--format json` with rc 2 and empty stdout, and the full hermetic suite still passes (T-001-02).
- [ ] Vulnerable fixture with only the fake dep-scan on PATH exits `1` with a `dep-scan/vulnerability` HIGH finding; clean fixture exits `0` (T-001-03, T-001-04).
- [ ] `_dep_scan_entries` behavior pinned: bare array → same list; `{"results": [...], "transitive": {...}}` → the results list; any other type → `[]` (T-001-05 … T-001-07).
- [ ] Per-policy mapping pinned: `block → HIGH`, `warn → MEDIUM`, `rule_id`, message content, manifest path (T-001-08).
- [ ] Warm-cache sentinel (`version: "cached"`, empty `policies`) still produces zero findings plus the stderr note (T-001-09).
- [ ] Fail-closed unchanged: unparseable JSON and rc-2-empty-stdout both raise `ToolError` → CLI exit `2` (T-001-10, T-001-11).
- [ ] Exit codes 0/1/2/64 unchanged end-to-end, including `64` for a bad `--severity-threshold` (T-001-12).
- [ ] `code-scanner/references/scan-commands.md` contains no `--json` dep-scan invocations (T-001-01).

## Verification plan

- **L5 (hermetic validation harness):** `python3 -m pytest tests/test_gate_cli.py -v` on a PATH of fake tools; quote the final pass count. This is the same harness TASK-001 used for its L5 evidence.
- **Static:** `grep -rn -- '--json' cli/code-scanner code-scanner/references/scan-commands.md` → no output.
- **Mutation check (proves the tests bite):** revert exactly one of the two flag edits in `run_dep_scan`, rerun the suite, confirm T-001-02/T-001-03 fail with the fake's diagnostic, then restore.
- **Optional real-tools pass:** with a real `dep-scan` binary on PATH, `CODE_SCANNER_REAL_TOOLS=1 python3 -m pytest tests/test_gate_cli.py -v -k real_tools` (environment-dependent; not the gate).

## Out of scope

- Gating on attributed cached verdicts and the Dockerfile pin: task 002 (`002-gate-cached-verdicts-and-shared-pin.md`).
- Adopting `--transitive` in the gate CLI (the skill uses it; the CLI does not; separate decision).
- Any change to dep-scan itself; this task must work against currently released dep-scan versions (the alias and the documented flag emit identical output).
- The osv-scanner and semgrep runners.

## Dependencies

None. Independent of dep-scan tasks 112/113; safe to land first.
