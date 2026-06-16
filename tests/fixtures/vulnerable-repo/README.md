# vulnerable-repo (L5 fixture)

A target with **two** planted issues:

1. **Known-vulnerable dependency** — `pyyaml==5.3.1` (CVE-2020-14343, CRITICAL).
   Flagged by the deterministic tier (OSV-Scanner / dep-scan). This is the
   **gating** finding → `error`-level SARIF result → non-zero exit.
2. **Planted CRITICAL pattern** — a download-and-execute (remote script piped to
   a shell) in [src/setup_env.sh](src/setup_env.sh). Flagged by the heuristic tier
   as an **advisory** (best-effort) finding — it does NOT by itself fail the
   gate (TASK-001 REQ-003).

Expected gate result: **exit 1**, with at least one `error`-level result whose
`tool.driver` is a deterministic tool, and the pattern finding tagged
`tier: best-effort` / non-gating.
