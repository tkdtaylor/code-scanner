# Security Policy

## Supported versions

Only the current `main` branch and the most recent tagged release receive
security fixes.

| Version | Security fixes |
|---------|---------------|
| `main` | ✅ Yes |
| `v1.1.0` (latest tag) | ✅ Yes |
| `< v1.1.0` | ❌ No |

## Reporting a vulnerability

**Please do not open a public GitHub issue for security vulnerabilities.**
A public report exposes the flaw to everyone before a fix is available.

### Option 1 — GitHub private vulnerability reporting (preferred)

Use GitHub's built-in private advisory flow:
<https://github.com/tkdtaylor/code-scanner/security/advisories/new>

GitHub keeps the report confidential and notifies only maintainers.

### Option 2 — Email

Send a report to <tools@taylorguard.me> with:

- A concise description of the vulnerability
- Reproduction steps (target type, command line, scan mode)
- The commit, tag, or `main` state you observed it on
- Your assessment of severity (CVSS or plain English is fine)
- Any suggested mitigations

## Response expectations

- **Acknowledgement:** within 7 days of receipt.
- **Status update:** within 30 days (triaged, confirmed, or declined with
  reasoning).
- **Fix shipped:** within 90 days for confirmed vulnerabilities. Critical
  issues (CVSS ≥ 9.0) target a 14-day patch window. If more time is needed
  we will coordinate a disclosure date with the reporter.

## Scope

**In scope:**

- Sandbox-escape paths: any way a scanned target can execute code on the
  host (the core promise is that remote targets are analyzed inside a
  disposable Docker sandbox and local targets are read, never executed)
- The headless CLI gate mode's exit-code contract (a malicious target that
  causes a false PASS)
- Detection bypasses that defeat a documented check via crafted repo/package
  content (e.g. SARIF self-validation, semgrep ruleset evasion by encoding
  tricks the docs claim are covered)
- Credential or filesystem exposure from the scanning container into the host

**Out of scope:**

- Vulnerabilities in Docker itself, semgrep, or other bundled third-party tools
  (report upstream; we will pin/upgrade)
- Detection gaps for threat classes the documentation does not claim to cover
  (those are feature requests)
- Findings that require an already-compromised host
- The sample malware reports under `sample-reports/` (they intentionally quote
  hostile code)

## Recognition

Reporters are credited in the changelog and release notes unless they
request anonymity. We do not currently offer a bug bounty.

## Maintainer note

After merging this file, enable **Settings → Code security and analysis →
Private vulnerability reporting** in the GitHub repository settings so the
"Report a vulnerability" button is visible on the repo page.
