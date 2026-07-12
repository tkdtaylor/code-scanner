# Test Spec — Task 002: Gate on attributed cached verdicts; shared PINNED_VERSION pin

Part (a) tests live in `tests/test_gate_cli.py` (hermetic; monkeypatch/e2e conventions identical to the task 001 test spec: `cs` is the loaded CLI module, unit tests monkeypatch `cs._have`/`cs._run`, the tmp manifest fixture is `requirements.txt` containing `pyyaml==5.3.1\n`). Part (b) tests are docker-build assertions, runnable as a shell script or an opt-in pytest marker (they need Docker and network to github.com; they are still deterministic because the version is injected via `--build-arg`).

The canned **attributed cached entry** used below (the dep-scan task 112 shape; adjust the provenance key to whatever dep-scan's updated `docs/spec/interfaces.md` names it, in exactly one place at the top of the test file):

```json
{
  "package": "PyYAML",
  "version": "5.3.1",
  "registry": "pypi",
  "age_hours": null,
  "result": "block",
  "reason": "Found known vulnerability(ies): GHSA-8q59-q68h-6hv4",
  "provenance": "cache",
  "policies": [
    {"policy_name": "age", "result": "pass", "reason": null},
    {"policy_name": "vulnerability", "result": "block", "reason": "Found known vulnerability(ies): GHSA-8q59-q68h-6hv4"}
  ]
}
```

The canned **legacy sentinel entry** (pre-112 warm-cache shape):

```json
{"package": "PyYAML", "version": "cached", "registry": "pypi", "age_hours": null, "result": "block", "reason": "cached result", "policies": []}
```

## Part (a): gating on attributed cached verdicts

### T-002-01: Attributed cached block gates as HIGH
- Arrange: stub `cs._run` returns `(1, json.dumps([<attributed cached entry>]), "")`.
- Act: `findings = cs.run_dep_scan(str(tmp_path))` with `capsys`.
- Expected: exactly 1 finding; `rule_id == "dep-scan/vulnerability"`; `severity == "HIGH"`; `message == "PyYAML@5.3.1: Found known vulnerability(ies): GHSA-8q59-q68h-6hv4"` (real version in the message, no cache-specific wording); `tier == cs.TIER_DETERMINISTIC`; stderr does **not** contain `not gating`.

### T-002-02: Gating is provenance-field-agnostic
- Arrange: same entry with the provenance key deleted.
- Act/Expected: findings identical to T-002-01, field for field. (Negative mutation guard: if the implementation keys gating on the provenance field, this test and T-002-01 cannot both pass.)

### T-002-03: Legacy sentinel still refuses to gate
- Arrange: stub returns `(1, json.dumps([<legacy sentinel entry>]), "")`.
- Act: `cs.run_dep_scan(str(tmp_path))` with `capsys`.
- Expected: returns `[]`; stderr contains `legacy` (the updated note) and the package name `PyYAML`; stderr does not claim a finding was gated.

### T-002-04: Attributed cached warn maps to MEDIUM
- Arrange: attributed cached entry with `result: "warn"` and its `vulnerability` policy replaced by `{"policy_name": "typosquatting", "result": "warn", "reason": "similar to 'pyaml'"}`.
- Expected: exactly 1 finding; `severity == "MEDIUM"`; `rule_id == "dep-scan/typosquatting"`; `message == "PyYAML@5.3.1: similar to 'pyaml'"`.

### T-002-05: Mixed batch gates only the attributed entry
- Arrange: stub returns both canned entries in one array (attributed first, legacy second; also run the reversed order).
- Expected: exactly 1 finding in both orders (`dep-scan/vulnerability`, HIGH); stderr carries the legacy note exactly once per run.

### T-002-06: E2E, attributed cached mode exits 1
- Arrange: `tests/fake-tools/dep-scan` run with `FAKE_DEPSCAN_MODE=cached-attributed` (fake emits the attributed cached entry array for the vulnerable fixture, `[]` for clean; exit 1/0 respectively).
- Act: `run_cli(VULN, path=fake_path(), env_extra={"FAKE_DEPSCAN_MODE": "cached-attributed"})`.
- Expected: rc `1`; SARIF contains an error-level result with `ruleId == "dep-scan/vulnerability"` in the `dep-scan` run whose `properties.gating` is `true`.

### T-002-07: E2E, legacy mode exits 0 and warns
- Act: `run_cli(VULN, path=fake_path(), env_extra={"FAKE_DEPSCAN_MODE": "cached-legacy"})`.
- Expected: rc `0` (nothing else in the fixture gates via the fake PATH at the default HIGH threshold: the planted curl|bash pattern is advisory-tier); stderr contains the legacy-shape note; SARIF's `dep-scan` run has zero error-level results.
- (This is the load-bearing fail-closed assertion: a top-level `block` without policy attribution must not flip the exit code.)

### T-002-08: Fake tool modes are themselves pinned
- Run `tests/fake-tools/dep-scan` as a subprocess with cwd/argv marking the vulnerable fixture, once per mode.
- Expected: `FAKE_DEPSCAN_MODE=cached-attributed` stdout parses to an array whose single entry has `version == "5.3.1"` and a non-empty `policies` list; `FAKE_DEPSCAN_MODE=cached-legacy` stdout entry has `version == "cached"` and `policies == []`; unset mode keeps today's fresh-scan shape byte-compatible (existing tests unchanged).

## Part (b): Dockerfile pin from PINNED_VERSION

### T-002-09: Static Dockerfile contract
- Read `code-scanner/docker/Dockerfile.dep-scan` as text.
- Expected, all of:
  - no line matches the independent-pin regex `VERSION="v[0-9]` (the old hardcode);
  - contains `PINNED_VERSION` (the channel URL) and `ARG DEP_SCAN_VERSION`;
  - contains `test -n "$VERSION"` (empty-pin fail-closed);
  - contains a `dep-scan --version` invocation piped to a `grep` on the resolved version (build-time verification).

### T-002-10: Deterministic positive build via build-arg
- Act: `docker build -f code-scanner/docker/Dockerfile.dep-scan --build-arg DEP_SCAN_VERSION=<known-good tag, e.g. v1.3.1> -t dep-scan:t002 .` then `docker run --rm --entrypoint dep-scan dep-scan:t002 --version`.
- Expected: build exits 0; the version output contains the tag without the leading `v` (e.g. `1.3.1`). This proves the verification step passes on a genuine match.

### T-002-11: Bogus version fails the build (fail closed)
- Act: `docker build ... --build-arg DEP_SCAN_VERSION=v0.0.0 ...`.
- Expected: build exits non-zero (release download 404s); no image tagged.

### T-002-12: Channel path (run only after dep-scan task 113 lands)
- Act: `docker build` with no `DEP_SCAN_VERSION` build-arg; separately `curl -fsSL https://raw.githubusercontent.com/tkdtaylor/dep-scan/main/PINNED_VERSION`.
- Expected: build succeeds and the image's `dep-scan --version` output contains the fetched pin (stripped of `v` and whitespace). Until 113 lands this build must fail closed (curl `-f` non-zero → build fails), which can be asserted today.

## Comment/caveat hygiene

### T-002-13: Stale caveat text updated
- Static greps:
  - `cli/code-scanner` no longer contains `likely a cache hit` (the old note); the refusal branch's message contains `legacy`.
  - `tests/test_gate_cli.py`'s `test_real_tools_vulnerable_repo` comment no longer gives "unattributable cached result sentinel" as the skip rationale (osv-scanner requirement itself remains).

## Regression

### T-002-14: Task 001 suite unchanged
- All T-001-* tests still pass; in particular T-001-09 is superseded: update it to assert the new legacy-note wording rather than deleting it (the zero-findings expectation is identical).
- `python3 -m pytest tests/test_gate_cli.py -v` → 0 failures.
