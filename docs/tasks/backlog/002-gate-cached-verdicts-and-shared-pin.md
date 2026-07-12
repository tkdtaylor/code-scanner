# Task 002 — Gate on attributed cached verdicts; build Dockerfile.dep-scan from the shared PINNED_VERSION

**Status:** backlog (blocked until dep-scan tasks 112 and 113 land)
**Depends on:** code-scanner task 001 (`001-depscan-json-contract.md`); dep-scan task 112 (cached-verdict full attribution); dep-scan task 113 (`PINNED_VERSION` file)
**Test spec:** [`../test-specs/002-gate-cached-verdicts-and-shared-pin-test-spec.md`](../test-specs/002-gate-cached-verdicts-and-shared-pin-test-spec.md)

## Objective

Two consumer-side follow-ups to dep-scan's cache and version-pin contracts, one responsibility (consume the new contracts):

(a) Gate on dep-scan cached verdicts once they carry full attribution: remove the cache-hit gating exclusion in `run_dep_scan` while keeping the refusal for unattributed legacy shapes.
(b) Build `code-scanner/docker/Dockerfile.dep-scan` from dep-scan's `PINNED_VERSION` file instead of this repo's independent hardcoded pin.

## Context

The current caveat this task removes, stated verbatim: cached verdicts are unattributable so the supply-chain tier silently drops out of gating on warm cache, with osv-scanner as the compensating control.

Concretely, today dep-scan reconstructs a warm-cache verdict as `{"package": <name>, "version": "cached", "age_hours": null, "result": <pass|warn|block>, "reason": "cached result", "policies": []}` (its `CheckResult` cache-hit path). `run_dep_scan` in `cli/code-scanner` gates only on entries with attributable policy violations (`violating = [p for p in entry.get("policies") ...]`); a bare top-level `block`/`warn` with empty `policies` prints the stderr note "dep-scan gave an unattributable '<result>' for <name> (no policy detail — likely a cache hit); not gating" and is skipped. The same caveat appears in `tests/test_gate_cli.py` (`test_real_tools_vulnerable_repo` skips unless osv-scanner is present, with a comment explaining that dep-scan's cache "can collapse a real verdict into an unattributable 'cached result' sentinel").

**dep-scan task 112** (planned, sibling repo) gives cached verdicts full attribution: the real resolved version instead of the literal `"cached"`, the full `policies` array as recorded at scan time, and an additive cache-provenance field on the entry; the `version: "cached"` sentinel is removed. Because the existing gating filter keys on the `policies` array, an attributed cached verdict gates *by construction* once 112 lands; the code change here is narrowing the refusal branch to legacy shapes only and updating the caveat text in code comments and tests.

**dep-scan task 113** (planned, sibling repo) adds a machine-readable `PINNED_VERSION` file at the dep-scan repo root defining the single ecosystem version pin. Today `code-scanner/docker/Dockerfile.dep-scan` hardcodes its own pin (`VERSION="v1.3.1"` inside the download `RUN`), independent of the pin in sibling repos (reverse-engineer currently pins v1.2.1: drift in the wild). This Dockerfile is the image the conversational skill auto-builds ("built automatically on first scan and after Dockerfile changes", `code-scanner/SKILL.md`; pre-build command documented in `README.md`). It downloads over TLS from GitHub releases without SHA pinning, so fetching the pin at build time is consistent with its existing trust model.

**Confirmed against dep-scan's shipped `docs/spec/interfaces.md` (tasks 112/113 merged, dep-scan commit `40f3007`/`a53752e`):**

- The additive cache-provenance field is **not** a flat `"provenance": "cache"` string as assumed above. It is a nested `cache` object, present only on an attributed cache hit: `"cache": {"hit": true, "scanned_at": "<RFC3339>", "dep_scan_version": "<semver>"}`, omitted entirely on a fresh scan (`serde(skip_serializing_if = "Option::is_none")`). `cache.hit` is always `true` when the key is present; its presence alone signals a hit. The gating logic in `run_dep_scan` does not read this field at all (REQ-002-04): it keys only on `policies`, so it is agnostic to the field's shape by construction.
- `PINNED_VERSION`: repo root, raw URL `https://raw.githubusercontent.com/tkdtaylor/dep-scan/main/PINNED_VERSION`, format confirmed exactly as assumed: single line `"v" + semver + "\n"` (e.g. `v1.3.1\n`), LF only. dep-scan's own README documents the Docker consumer pattern as `install.sh --version=<pin>` (sha256sum-verified against published checksums), which this task's Dockerfile now uses instead of an independent tarball fetch.

## Files and functions (exact)

| File | What changes |
|---|---|
| `cli/code-scanner` | `run_dep_scan(target)`: the unattributable-entry branch (the `if not violating:` block) and the docstring/comment that states the cache caveat. |
| `code-scanner/docker/Dockerfile.dep-scan` | Version resolution in the download `RUN`; new post-install verification step. |
| `tests/fake-tools/dep-scan` | Two new env-selected output modes (attributed-cached, legacy-sentinel). |
| `tests/test_gate_cli.py` | New tests per test spec; update the `test_real_tools_vulnerable_repo` skip comment (osv-scanner stays required there because the assertion is a version-specific CVE, but the "unattributable cache sentinel" rationale is obsolete after 112). |

## Part (a): gating behavior (exact before/after)

Before (today): any entry whose `policies` yield no `block`/`warn` is skipped; if its top-level `result` is `block`/`warn`, stderr gets the "unattributable ... not gating" note. On warm cache this silently drops the whole supply-chain tier out of gating.

After:

1. Entries with a non-empty violating-policies list gate exactly as today (`block → HIGH`, `warn → MEDIUM`, `rule_id = "dep-scan/<policy_name>"`). This is unchanged code; with 112 landed it now also covers cached verdicts, because they carry the full `policies` array and real `version`.
2. The refusal branch stays, narrowed and relabeled: an entry with top-level `result` in (`block`, `warn`) and no violating policies (which after 112 can only come from a pre-112 dep-scan binary, i.e. `version == "cached"` / empty `policies`) still does not gate, and the stderr note is updated to say it is a legacy unattributed shape from an older dep-scan and to name the remediation (upgrade dep-scan to the pinned version). Fail-closed posture unchanged: never gate on an unattributable verdict.
3. The gating decision must not read the provenance field. Attributed entries with and without it produce identical findings (tolerates both fresh and cached verdicts, and insulates us from the field's final name).
4. Message content for a cached verdict uses the entry's real `version` field like any other entry: `"<name>@<version>: <policy reason>"`. No cache-specific wording in the SARIF result.

Exit codes 0/1/2/64 and all other fail-closed rules are untouched.

## Part (b): Dockerfile pin (exact before/after)

Before (`code-scanner/docker/Dockerfile.dep-scan`, download `RUN`): `VERSION="v1.3.1"` hardcoded.

After:

```dockerfile
ARG DEP_SCAN_VERSION=""
# single ecosystem pin: dep-scan's PINNED_VERSION file (dep-scan task 113).
# Override for hermetic tests/rollback: --build-arg DEP_SCAN_VERSION=v1.3.1
RUN ARCH=$(uname -m) && \
    case "$ARCH" in \
      x86_64|amd64)  TARGET="x86_64-unknown-linux-gnu" ;; \
      aarch64|arm64) TARGET="aarch64-unknown-linux-gnu" ;; \
      *) echo "Unsupported architecture: $ARCH" && exit 1 ;; \
    esac && \
    VERSION="${DEP_SCAN_VERSION:-$(curl -fsSL https://raw.githubusercontent.com/tkdtaylor/dep-scan/main/PINNED_VERSION | tr -d '[:space:]')}" && \
    test -n "$VERSION" && \
    curl -fsSL "https://github.com/tkdtaylor/dep-scan/releases/download/${VERSION}/dep-scan-${VERSION}-${TARGET}.tar.gz" \
      -o /tmp/dep-scan.tar.gz && \
    tar xzf /tmp/dep-scan.tar.gz -C /usr/local/bin && \
    chmod +x /usr/local/bin/dep-scan && \
    rm /tmp/dep-scan.tar.gz && \
    dep-scan --version | grep -F -- "${VERSION#v}"
```

Rules encoded above, which the implementation must keep even if the exact shell differs:

- `--build-arg DEP_SCAN_VERSION=vX.Y.Z` overrides the channel (deterministic builds in tests; emergency rollback).
- Empty resolved version fails the build (`test -n`): a 404/empty `PINNED_VERSION` fetch must not fall through to an unpinned install.
- Post-install verification: the build fails unless `dep-scan --version` output contains the resolved version string without the leading `v` (the "verify the installed version matches the pin at image build" gate).
- No independent literal pin remains in the file.

Adjust the URL/filename if dep-scan task 113 lands with a different location or format. Keep the existing labels and the `dev.code-scanner.dockerfile-hash` auto-rebuild mechanism untouched (content change alone triggers the skill's rebuild).

## Step-by-step outline

1. Read dep-scan's updated `docs/spec/interfaces.md` (post-112/113); record the provenance field key and the `PINNED_VERSION` path/format in this task file before coding.
2. Part (a): narrow the `if not violating:` branch in `run_dep_scan` per rules 1 to 4 above; update the docstring and the stale caveat comment; update the `test_real_tools_vulnerable_repo` comment.
3. Extend `tests/fake-tools/dep-scan`: `FAKE_DEPSCAN_MODE=cached-attributed` emits the 112 cached shape (real version, full policies, provenance field); `FAKE_DEPSCAN_MODE=cached-legacy` emits the old sentinel (`version: "cached"`, empty policies, top-level `block`). Default behavior unchanged.
4. Add tests T-002-01 … T-002-07 (unit + e2e; see test spec).
5. Part (b): rewrite the Dockerfile download `RUN` as above; run the docker build assertions T-002-08 … T-002-10.
6. `python3 -m pytest tests/test_gate_cli.py -v` green; static greps green.

## Acceptance criteria

- [ ] Attributed cached verdict (real version, non-empty `policies`, provenance field present) with a `block` policy produces a HIGH `dep-scan/<policy>` finding and no "not gating" stderr note (T-002-01).
- [ ] Same entry without the provenance field produces identical findings: gating is provenance-field-agnostic (T-002-02).
- [ ] Legacy sentinel (`version: "cached"`, empty `policies`, top-level `block`) still produces zero findings plus a stderr note mentioning the legacy shape (T-002-03).
- [ ] `warn` policy on a cached verdict maps to MEDIUM (T-002-04).
- [ ] Mixed batch (one attributed cached block + one legacy sentinel) yields exactly one finding (T-002-05).
- [ ] E2E: fake in `cached-attributed` mode on the vulnerable fixture exits `1`; in `cached-legacy` mode exits `0` with the stderr note (T-002-06, T-002-07).
- [ ] Dockerfile: no independent literal pin; references `PINNED_VERSION`; has the `--build-arg` override and the `dep-scan --version` build-time verification (T-002-08 static).
- [ ] `docker build --build-arg DEP_SCAN_VERSION=<known good>` succeeds and the image's `dep-scan --version` matches; a bogus version fails the build (T-002-09, T-002-10).
- [ ] Stale caveat comments updated in `cli/code-scanner` and `tests/test_gate_cli.py` (T-002-11).
- [ ] Full suite green: `python3 -m pytest tests/test_gate_cli.py -v`.

## Verification plan

- **L5 hermetic (part a):** `python3 -m pytest tests/test_gate_cli.py -v` with fake tools; quote pass count. Mutation check: delete the narrowed refusal branch entirely, confirm T-002-03/T-002-07 fail (legacy sentinel would gate); restore.
- **L5 deterministic build (part b):** `docker build -f code-scanner/docker/Dockerfile.dep-scan --build-arg DEP_SCAN_VERSION=<current pin> -t dep-scan:test .` then `docker run --rm --entrypoint dep-scan dep-scan:test --version`; quote the output and match it to the pin. Negative: `--build-arg DEP_SCAN_VERSION=v0.0.0` must exit non-zero (release 404, fail closed). Requires Docker + network to github.com (the image build is inherently networked; determinism comes from the pinned build-arg).
- **L5 channel path (part b, only after dep-scan 113 lands):** `docker build` with **no** build-arg; confirm the installed version equals the content of dep-scan's `PINNED_VERSION`.
- **Optional real-tools (part a, only after dep-scan 112 lands):** with the new dep-scan release on PATH, scan `tests/fixtures/vulnerable-repo` twice; on the second (warm-cache) run assert exit `1` and a `dep-scan/vulnerability` finding in the SARIF, proving the warm-cache dropout is gone end to end. Record this as the task's strongest evidence.

## Out of scope

- reverse-engineer's dep-scan image (that repo's task `001-shared-depscan-pin.md` consumes the same channel with its own SHA-pinning design).
- Switching the gate CLI or skill to `--transitive`.
- Removing the osv-scanner requirement from `test_real_tools_vulnerable_repo` (the version-specific CVE assertion still needs a version-aware, cache-stable scanner; only the comment's rationale changes).
- Any SHA256 pinning of the dep-scan release tarball in this Dockerfile (would be new scope; this repo's image trusts TLS + GitHub releases today).
- dep-scan-side changes (tasks 112/113 live in the dep-scan repo).

## Dependencies

- code-scanner task 001 (lands the `--format json` invocation and the parsing regression tests this task builds on).
- dep-scan task 112: without it, attributed cached verdicts do not exist and part (a) cannot be verified at L5; do not start part (a) before it lands.
- dep-scan task 113: without it, the `PINNED_VERSION` fetch 404s and only the `--build-arg` override path of part (b) is testable; do not merge part (b) before it lands.
