# `code-scanner` — headless CLI gate mode

A deterministic, non-interactive scanner entrypoint for CI / verification gates.
Emits a process **exit code** and machine-readable **SARIF** (ADR-001). This is an
*additional* entrypoint — the conversational Agent Skill (`../code-scanner/SKILL.md`)
is unchanged (TASK-001 REQ-007).

```
code-scanner [TARGET] [--sarif PATH] [--severity-threshold LEVEL]
code-scanner --version
```

`TARGET` defaults to the current working directory — the shape agent-builder's
gate uses (`CodeScannerStep` runs bare `code-scanner` with the worktree as cwd).

## Reliability tiers (ADR-001)

| Tier | Source | Role |
|------|--------|------|
| **deterministic** | OSV-Scanner, Semgrep, dep-scan (native output) | **Gates** the build |
| **best-effort** | heuristic pattern library | **Advisory** only — never gates |

The gating exit code derives from the **deterministic tier only** (REQ-003). A
planted pattern match is reported (at its mapped level) but cannot by itself fail
the gate. Severity → SARIF level is fixed: CRITICAL/HIGH → `error`, MEDIUM →
`warning`, LOW/INFO → `note`. Each tool gets its own SARIF `run` with a
`tool.driver.name`, tagged `codeScannerTier` / `gating`, so consumers can weight
the tiers.

## Exit codes (REQ-002)

| Code | Meaning |
|------|---------|
| `0`  | clean — no gating findings at/above the threshold |
| `1`  | gating findings present (deterministic tier) |
| `2`  | tool/setup failure — a tool errored, or no deterministic tool was available |
| `64` | usage error (bad arguments / target not a directory) |

`2` is **fail-closed**: if zero deterministic tools are on PATH, the scan cannot
certify anything and refuses to report clean. The CLI also structurally
self-validates the SARIF it builds before emitting; if it ever produces malformed
SARIF (an internal bug) it returns `2` rather than shipping bad output to a
consumer.

## Runtime dependencies (REQ-006 / ADR-002)

Socket-less native-tools execution model — **no Docker/Podman socket required**.
Provision these on `PATH` (they `cp` into a `--gate-tools` dir and mount into a
rootless execution-box like `golangci-lint` and `gods`):

- [`osv-scanner`](https://github.com/google/osv-scanner) — known-vulnerability lookup (version-aware).
- [`semgrep`](https://semgrep.dev) — static analysis (emits SARIF natively).
- [`dep-scan`](https://github.com/tkdtaylor/dep-scan) — supply-chain policy checks.

A missing tool reduces coverage (recorded as a stderr note); missing *all three*
is a fail-closed `2`. The CLI itself is a single stdlib-only Python 3 script — no
pip install, no compile step.

> **dep-scan caching caveat.** dep-scan keeps an on-disk cache; a cache hit can
> return a bare `block`/`warn` with no policy detail (`version: "cached"`, empty
> `policies`). Because that verdict is unattributable and not reproducible, the
> CLI does **not** gate on it (it logs a coverage note instead). For reproducible
> version-specific CVE gating, keep `osv-scanner` on PATH.

## Tests

```
python3 -m pytest tests/test_gate_cli.py            # hermetic (fake tools, no network)
CODE_SCANNER_REAL_TOOLS=1 python3 -m pytest tests/test_gate_cli.py -k real
```

The hermetic suite injects stub tools on PATH and asserts the exit-code + SARIF
contract against the L5 fixtures (`tests/fixtures/{clean,vulnerable}-repo`). The
opt-in suite runs the real binaries when present.
