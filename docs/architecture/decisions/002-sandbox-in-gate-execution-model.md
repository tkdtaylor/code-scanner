# ADR-002 — Sandbox-in-gate execution model (socketless native-tools mode)

**Status:** Accepted
**Date:** 2026-06-16
**Deciders:** code-scanner maintainer
**Depends on:** ADR-001 (SARIF findings format)
**Driven by:** TASK-001 (headless CLI gate mode) — resolves the open design decision its
*Consumer* section flags.

## Context

TASK-001 adds a headless `code-scanner` binary on `PATH` for use as a blocking verification-gate
step. The first consumer, **agent-builder**, runs its gate inside a **rootless-Podman
execution-box** and mounts gate tools (`golangci-lint`, `gods`, and now `code-scanner`) from a
`--gate-tools` dir.

The conversational skill's containment model (PLAN-v1, SKILL.md) leans on a **Docker/Podman
socket**: remote targets are downloaded into a disposable Docker *volume*, and even local-path
scans use Docker as a *tool-runner* — OSV-Scanner and dep-scan run in containers with the target
bind-mounted read-only. That socket dependency is exactly what is hard to satisfy inside a rootless
execution-box. TASK-001 calls out three candidate resolutions for the containment profile:

- **(a) docker-in-podman** — mount a Docker/Podman socket into the rootless execution-box so the
  scanner keeps using its container tool-runners.
- **(b) host-side scan** — run code-scanner on the host side of the execution-box seam, outside the
  rootless container, and pass results back in.
- **(c) socket-less native-tools mode** — run the deterministic tier as native binaries on `PATH`,
  no socket at all.

Two facts about the gate scenario narrow the choice:

1. **The gate target is always a trusted, already-checked-out worktree** (the gate's cwd). There is
   nothing to *download*, so the disposable-fetch sandbox — the one component that genuinely needs a
   socket — is not in play for gate mode. The sandbox exists to prevent *execution* of code fetched
   from an untrusted source; read-only static analysis of files already on disk executes nothing
   (this is the same reasoning the skill's Local Mode already uses).
2. **The deterministic tier's tools are all distributable static binaries.** The pattern greps
   already run natively in Local Mode. OSV-Scanner ships as a static Go binary; dep-scan ships as a
   release binary (the same one agent-builder's `gods` shim invokes — `gods` itself is dep-scan's
   `go`-command wrapper, so code-scanner calls the `dep-scan` binary directly); Semgrep is a
   pip-installable CLI. None of the three *needs* a container — the skill only used containers as a
   convenient tool-runner, not for isolation of these read-only steps.

## Decision

Adopt **(c) socket-less native-tools mode** as the execution model for headless gate mode.

The `code-scanner` gate CLI runs the deterministic tier by invoking **native binaries on `PATH`**
— `osv-scanner`, `semgrep`, and `dep-scan` — against the target worktree directly.
**No Docker/Podman socket is required**, so the binary and its three companion tools
`cp` into the `--gate-tools` dir and mount into the rootless execution-box exactly the way
`golangci-lint` and `gods` already do (REQ-006).

This decision applies **only to the headless gate CLI**. The conversational skill (SKILL.md) is
**unchanged** (REQ-007): it keeps its disposable-Docker sandbox for untrusted remote targets, which
is the right model when a human pastes an arbitrary GitHub URL or package name. The two surfaces
make different trust assumptions because they face different inputs — the gate scans code the
orchestrator already checked out and is about to build; the skill scans code of unknown provenance.

### Coverage / fail-closed contract

Native mode trusts whatever tools are present on `PATH`. To keep the gate honest:

- Each deterministic tool that is **present** is run; one that is **absent** is recorded as reduced
  coverage (a `skipped` note in the SARIF/summary), not silently ignored.
- If **zero** deterministic tools are available, the scan cannot certify anything and exits with the
  **tool-failure** code (fail-closed) — the gate must never pass green on an empty scan.
- A tool that is present but **errors** (crash, unpar-seable output) is also a tool-failure, not a
  clean result.

This contract is defined in TASK-001's exit-code table and surfaced in the CLI `--help`.

## Consequences

- **+** Satisfies REQ-006 with zero socket: `code-scanner` + `osv-scanner` + `semgrep` + `dep-scan`
  mount into the rootless execution-box like any other gate tool. No nested-container privilege.
- **+** Deterministic and reproducible — no container pulls, no daemon state; the same worktree and
  the same pinned tool versions always produce the same exit code (the property a gate requires).
- **+** Faster in the gate hot path (no per-step container startup).
- **+** Keeps the skill's stronger isolation exactly where it matters (untrusted remote fetch) and
  spends none of it where it doesn't (a trusted local worktree).
- **−** The gate host/image must provision the three tools on `PATH`; their versions must be pinned
  in the gate toolchain manifest (REQ-008 `--version` supports this). Missing tools degrade coverage
  rather than failing loudly unless *all* are missing.
- **−** Loses container-level isolation for the tool runs themselves. Accepted: these are read-only
  analyzers over a worktree the gate already trusts enough to build; they execute no target code.
- **−** Rejected **(a)** because socket-passthrough into rootless Podman reintroduces the privilege
  and nesting hazard the rootless execution-box exists to avoid; rejected **(b)** because running the
  scan outside the box violates the execution-box seam and the audit-trail boundary.

## References

- TASK-001 — Headless CLI gate mode (*Consumer* section: the (a)/(b)/(c) framing)
- ADR-001 — SARIF findings format (two-tier reliability model; gating derives from the
  deterministic tier only)
- dep-scan `shims/gods` — prior art for a `cp`-able native shim agent-builder already mounts
- agent-builder Task 033 — Execution-box gate toolchain (the `--gate-tools` mount mechanism)
