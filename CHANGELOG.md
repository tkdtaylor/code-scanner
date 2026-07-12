# Changelog

All notable changes to code-scanner are documented here.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and the project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- **Headless CLI gate mode** — `code-scanner` on PATH with a machine-checkable
  exit-code contract (ADR-002), SARIF self-validation before emit (fail closed
  on malformed output), and a containerized real-tools integration runner.
- Agentic **skill + MCP-server threat coverage** (prompt injection, embedded
  commands, exfiltration, excessive agency, memory poisoning, trigger abuse).
- Rust (`Cargo.lock`) and Go (`go.sum`) transitive dependency scanning via
  dep-scan (now pinned at v1.3.1), with crates.io + Go proxy/sumdb on the
  network allow-lists.
- SARIF findings format adopted as the report interchange format (ADR-001).
- Semgrep pinned to a bundled offline ruleset (no `--config auto` network
  dependency at scan time).
- SECURITY policy, code of conduct, and this changelog.

### Changed

- **Relicensed to Apache-2.0** (from PolyForm Noncommercial 1.0.0), with SPDX
  headers, NOTICE, DCO sign-off, and contribution guide.
- Rebranded from CodeScan to Code Scanner.

### Fixed

- Every `dep-scan check` invocation (headless gate CLI and the
  `scan-commands.md` skill reference) now uses the documented, stable
  `--format json` contract instead of the deprecated `--json` alias. No
  behavior change; guards against the alias disappearing on a future dep-scan
  major version.

## [1.1.0] — 2026-03-22

### Added

- Vulnerability scan and download size check.
- Docker Sandbox (sbx) compatibility; local mode (skip the Docker sandbox for
  local-path targets, which are read, never executed).
- dep-scan supply-chain analysis integration; LiteLLM-class supply-chain
  attack detection.

## [1.0.0] — 2026-03-21

### Added

- Initial release: sandboxed scanning of GitHub repos, PyPI/npm packages, and
  archives for malicious code, backdoors, and credential harvesting, with a
  disposable Docker sandbox for everything downloaded from an untrusted source.
