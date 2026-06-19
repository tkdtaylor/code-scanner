# Contributing to code-scanner

Thanks for helping improve code-scanner. Issues and PRs are welcome.

## License of contributions

code-scanner ships under the [Apache License 2.0](LICENSE) — free to use, modify, and distribute, including in commercial and proprietary products. By contributing, you agree your contributions are licensed under Apache-2.0. Under Apache-2.0 §5, contributions are inbound=outbound — they become part of the project and usable by everyone, including commercially. **No CLA is required.**

We use the [Developer Certificate of Origin (DCO)](https://developercertificate.org/) instead of a CLA. Certify you wrote (or have the right to submit) the change by signing off every commit:

```bash
git commit -s -m "your message"
```

This appends `Signed-off-by: Your Name <you@example.com>` (must match your git identity). A CI check enforces it on every PR. To fix a commit you forgot to sign off: `git commit --amend -s --no-edit`.

## What to contribute

- **Detection patterns** — new malware / supply-chain / agentic-skill threat indicators. Keep patterns original, grep-oriented expressions; do not copy source from third-party projects (credit ideas in [ATTRIBUTIONS.md](ATTRIBUTIONS.md)).
- **Bug fixes and docs** — always welcome.
- For non-trivial changes, open an issue first so we can agree on the approach.

## Security issues

Please do **not** open public issues for vulnerabilities. Email **tools@taylorguard.me** and we'll coordinate a fix and disclosure.
