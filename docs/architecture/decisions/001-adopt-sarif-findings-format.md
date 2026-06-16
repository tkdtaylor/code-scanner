# ADR-001 — Adopt SARIF as the machine-readable findings format

**Status:** Accepted
**Date:** 2026-06-03 (accepted 2026-06-16)
**Deciders:** code-scanner maintainer

> This is the first ADR in code-scanner; it also establishes the
> `docs/architecture/decisions/` convention for the project (mirroring the sibling
> `armor` and `dep-scan` repos).

## Context

code-scanner is a portable Agent Skill that scans repos / packages / archives for malicious
patterns, suspicious links, and supply-chain indicators, and writes a **human-readable Markdown
report** to `./code-scanner-reports/`. It already orchestrates the OSV database and `dep-scan`
for dependency checks.

It is one block in a composable, security-first agent ecosystem (cross-block design in
`agent-prep/outputs/foundations/interface-contracts.md`). A cross-cutting principle there:
**reuse existing interchange standards rather than invent new formats**, so a block's output is
interoperable and the block stays swappable.

Today code-scanner has only the Markdown surface. That is ideal for a human reviewer but is not
machine-ingestible: CI gates, code-review tooling, GitHub code scanning, and the agent's
audit-trail all want structured findings. The established standard for static-analysis results
is **SARIF** (Static Analysis Results Interchange Format, OASIS) — natively consumed by GitHub
code scanning, VS Code, and most security tooling.

## Decision

Add a **SARIF export alongside** the existing Markdown report (Markdown stays the primary human
surface; SARIF is the machine surface — they are generated from the same findings model).

- Each finding maps to a SARIF `result` with a stable `ruleId`, a `level`
  (`error`/`warning`/`note` ← CRITICAL/HIGH → error, MEDIUM → warning, LOW/INFO → note),
  `locations` (file + region), and a `message`.
- Rule metadata (description, help URI) lives in `tool.driver.rules`.
- Where an orchestrated upstream tool already emits SARIF (e.g. Semgrep, and OSV-Scanner's SARIF
  output), **aggregate its native SARIF** into the combined run rather than re-deriving findings.
- SARIF output is opt-in via a flag/skill-arg; default behaviour (Markdown) is unchanged.

**Skill-nature caveat.** code-scanner is an *instruction-driven Agent Skill*, not a deterministic
SAST binary. SARIF emission therefore has two reliability tiers: **(a) deterministic** — the native
SARIF aggregated from orchestrated tools (OSV-Scanner, Semgrep); **(b) best-effort** — the skill's
own pattern findings (`references/patterns.md`), which Claude serializes to SARIF and which inherit
the skill's non-determinism. The SARIF file should mark which results came from which tier
(`tool.driver` per source) so consumers can weight them accordingly.

## Consequences

- **+** Findings become ingestible by GitHub code scanning, CI policy gates, and the agent's
  audit-trail; dedup and triage across runs become possible.
- **+** Interop with the rest of the ecosystem and the broader SAST tool world; reinforces the
  "swappable block" goal.
- **−** Requires a stable internal findings model and a SARIF serializer; severity→level mapping
  must be defined once and kept consistent.
- **−** Aggregating heterogeneous upstream SARIF (differing rule namespaces) needs care to avoid
  ID collisions.

## References

- SARIF 2.1.0 (OASIS standard)
- Ecosystem standards table: `agent-prep/outputs/foundations/interface-contracts.md` §1a
- First realization: TASK-001 (headless CLI gate mode) emits this SARIF; ADR-002 defines its
  socket-less execution model. The two-tier reliability model here is load-bearing there — the
  gating exit code derives from the deterministic tier only.
