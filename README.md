# code-scanner

[![License: Apache 2.0](https://img.shields.io/badge/license-Apache%202.0-blue.svg)](LICENSE)
[![Last commit](https://img.shields.io/github/last-commit/tkdtaylor/code-scanner)](https://github.com/tkdtaylor/code-scanner/commits)

**A malware scanner for code repositories, packages, and agent skills** — analyzes targets for known CVEs, malicious patterns, supply-chain attacks, and backdoors. Remote targets run inside a disposable Docker sandbox so nothing downloaded touches the host; local paths are scanned in place with read-only analysis. Returns a Markdown report or machine-readable SARIF for CI gates.

Works as a Claude Skill (or compatible agent skill in GitHub Copilot, Cursor, Windsurf, Kiro, Antigravity) and as a headless CLI for verification gates. Part of the [Secure Agent Ecosystem](#the-building-blocks), Apache-2.0 licensed.

> **Status.** Code-scanner scans repositories, packages (PyPI / npm), archives, and skill files for malware patterns and supply-chain indicators. The conversational skill path and headless CLI (SARIF + exit codes for gating) are both production. Windows/macOS Docker Sandbox (`sbx`) support is present; integration with agent-builder's gate is live.

## Contents

- [Quick start](#quick-start)
- [How it works](#how-it-works)
- [What it detects](#what-it-detects)
- [Use as a skill](#use-as-a-skill)
- [Use as a CLI (gates)](#use-as-a-cli-gates)
- [Tech stack](#tech-stack)
- [Sponsorship](#sponsorship)
- [Enterprise support](#enterprise-support)
- [License](#license)

## Quick start

As a **Claude Skill**, trigger it conversationally:

```
User: Scan this repo and tell me if it's safe to run: https://github.com/owner/repo
```

Claude will download the repo into a disposable Docker sandbox, check it for CVEs and malware patterns, and write a report to `./code-scanner-reports/scan-report-*.md`. Nothing from the remote repo touches your host.

As a **headless CLI** (for CI / verification gates):

```bash
code-scanner .                                    # scan current directory
code-scanner /path/to/repo                        # scan local directory on disk
code-scanner . --sarif out.sarif                 # emit SARIF for gate consumption
# exit code: 0 = clean · 1 = findings · 2 = tool error
```

`cli/code-scanner` scans local directories on disk, while remote URLs are scanned inside the Docker sandbox via the skill.

The skill works in Claude Code, GitHub Copilot (Agent Mode), Cursor, Windsurf, Kiro, and Antigravity. Install by copying `code-scanner/SKILL.md` and `code-scanner/references/` into your agent's skill directory. The CLI requires Python 3 + Docker (or just Python 3 for local-path targets).

## How it works

Two isolation strategies — **remote targets** use a disposable sandbox; **local paths** use native read-only analysis.

```
Remote target (GitHub URL, package, archive)
├─ Create Docker volume (isolated from host)
├─ Download target into volume (execute perms stripped)
├─ Scan with OSV-Scanner, Semgrep, dep-scan (--network none)
├─ Follow download URLs, inspect payloads in sandbox
├─ Write report to host (output only)
└─ Destroy volume (nothing leaves sandbox)

Local path (folder already on disk)
├─ Skip sandbox entirely
├─ Run grep/find against files in place, read-only
├─ No copy, no download, no volume
└─ Write report to ./code-scanner-reports/
```

**Why local mode is safe:** The sandbox prevents *execution* of untrusted code during installation (hooks, setup scripts, postinstall triggers). Read-only text analysis never executes the code it reads. If code is already on your disk, you already accepted the risk of its presence; scanning it with grep adds none.

## What it detects

**Code repositories and packages:**

| Category | Detection |
|----------|-----------|
| **CVE / Dependencies** | Known vulnerabilities (OSV database), typosquatting, package age < 48h, maintainer changes, dependency confusion, transitive-tree scanning (JS/TS `package-lock.json` / `pnpm-lock.yaml` / `yarn.lock` / `bun.lock`, Python `uv.lock` / `poetry.lock` / `Pipfile.lock` / `pylock*.toml`, Rust `Cargo.lock`, Go `go.sum`) |
| **Malware patterns** | Base64/hex payloads, eval/exec patterns, `curl \| bash`, credential harvesting, reverse shells, cryptominers, web shells, C2 infrastructure, persistence mechanisms |
| **Supply chain** | Malicious install hooks (postinstall, setup.py, `__init__.py`), Python `.pth` persistence, unpinned CI/CD actions |
| **Recursive payloads** | Secondary download URLs fetched and inspected inside the sandbox |

**Claude skill files:**

| Category | Detection |
|----------|-----------|
| **Injection** | Prompt injection, system-prompt leakage, instructions designed to override Claude behavior |
| **Identity** | Falsely claiming verification, attempting to replace Claude's role |
| **Exfiltration** | Instructions to send data to remote endpoints, credential access directives |
| **Agency** | Autonomous high-impact actions without human-in-the-loop, blanket tool grants, unsafe defaults |
| **Rogue agent** | Self-modifying skills, unauthorized cross-session persistence, MCP server threats |

Note: No automated tool guarantees safety. code-scanner detects known patterns; novel or sufficiently obfuscated threats may evade detection. Use results alongside your own judgment.

## Use as a skill

**Claude Code** (Mac/Linux):

```bash
git clone https://github.com/tkdtaylor/code-scanner /tmp/code-scanner
cp -r /tmp/code-scanner/code-scanner ~/.claude/skills/
```

The dep-scan Docker image builds itself on first scan (cached thereafter). To pre-build it: `docker build -t dep-scan:latest -f /tmp/code-scanner/code-scanner/docker/Dockerfile.dep-scan /tmp/code-scanner`

**GitHub Copilot, Cursor, Windsurf, Kiro, Antigravity:** Copy `code-scanner/SKILL.md` and `code-scanner/references/` to your agent's `.github/skills/`, `.cursorrules`, `.windsurfrules`, `.kiro/steering/`, or equivalent skill directory. See `code-scanner/` folder structure for layout.

**Trigger phrases:** "Scan this repo for malware", "Is this npm package safe to install", "Check this GitHub URL before I run it", "Review this skill for injection attacks", or any phrasing that suggests evaluating code safety.

Add `--security-review` to force a supplementary Claude Code review even when no HIGH/CRITICAL findings are detected.

## Use as a CLI (gates)

```bash
code-scanner [TARGET] [--sarif PATH] [--severity-threshold LEVEL]
```

**Exit codes:**

| Code | Meaning |
|------|---------|
| `0` | Clean — no gating findings at or above threshold |
| `1` | Gating findings present (deterministic tools: OSV-Scanner, Semgrep, dep-scan) |
| `2` | Tool error or no deterministic tool available |
| `64` | Usage error |

**Reliability tiers:**

- **Deterministic** (OSV-Scanner, Semgrep, dep-scan) — gates the build
- **Heuristic** (pattern library) — advisory only, never gates

The CLI runs against a **bundled, offline Semgrep ruleset** (no registry fetch, reproducible across runs). Requires Python 3 and the native tools on PATH: `osv-scanner`, `semgrep`, `dep-scan`. Missing a tool reduces coverage but does not fail unless all deterministic tools are absent (fail-closed).

For Docker-based execution in rootless environments, see [cli/README.md](./cli/README.md).

## Tech stack

**Skill:** Claude Skill format (.md + references), Docker for remote-target sandboxing.

**CLI:** Python 3 (stdlib only, no dependencies), with native tool integration (OSV-Scanner, Semgrep, dep-scan).

See [docs/architecture/decisions/](./docs/architecture/decisions/) for design rationale (ADR-001: SARIF format, ADR-002: sandbox execution model).

## Sponsorship

code-scanner is independent, open-source security tooling. If it saves you time or risk, [sponsoring its development](https://github.com/sponsors/tkdtaylor) is the most direct way to keep it maintained.

## Enterprise support

Commercial support, integration help, and SLAs are available. Apache-2.0 means you can build on code-scanner freely; paid support is a partner if you want one, never a requirement. Contact [tools@taylorguard.me](mailto:tools@taylorguard.me).

## License

[Apache License 2.0](LICENSE) — free to use, modify, and distribute. See [NOTICE](NOTICE) for attribution and [CONTRIBUTING.md](CONTRIBUTING.md) for DCO contribution terms (inbound=outbound, no CLA). code-scanner is a block in the [Secure Agent Ecosystem](https://github.com/tkdtaylor/agent-builder#the-building-blocks); for runtime sandboxing see [exec-sandbox](https://github.com/tkdtaylor/exec-sandbox), for runtime defenses see [armor](https://github.com/tkdtaylor/armor), and for dependency scanning see [dep-scan](https://github.com/tkdtaylor/dep-scan).

---

For detailed setup, testing, and development, see [code-scanner/](./code-scanner/) (skill structure), [cli/](./cli/) (headless CLI contract), and [tests/](./tests/).
