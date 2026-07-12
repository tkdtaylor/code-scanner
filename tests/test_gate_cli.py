# SPDX-License-Identifier: Apache-2.0
"""L5 validation harness for the headless `code-scanner` gate CLI (TASK-001).

Two tiers of test:

* Hermetic (default): inject stub osv-scanner / dep-scan / semgrep on PATH that
  emit canned real-shape output. No network, no Docker. Exercises OUR exit-code,
  tier-gating, and SARIF-level logic against the two L5 fixtures.
* Real-tools (opt-in via CODE_SCANNER_REAL_TOOLS=1): run the actual binaries if
  present on PATH against the same fixtures. End-to-end but environment-dependent.

Run: python3 -m pytest tests/test_gate_cli.py -v
"""

import importlib.machinery
import importlib.util
import json
import os
import re
import shutil
import subprocess
import sys

import pytest

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _load_cli_module():
    """Import the extensionless `cli/code-scanner` shim as a module."""
    path = os.path.join(REPO, "cli", "code-scanner")
    spec = importlib.util.spec_from_file_location(
        "code_scanner_cli", path,
        loader=importlib.machinery.SourceFileLoader("code_scanner_cli", path),
    )
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


cs = _load_cli_module()
CLI = os.path.join(REPO, "cli", "code-scanner")
FIXTURES = os.path.join(REPO, "tests", "fixtures")
FAKE_TOOLS = os.path.join(REPO, "tests", "fake-tools")
CLEAN = os.path.join(FIXTURES, "clean-repo")
VULN = os.path.join(FIXTURES, "vulnerable-repo")

EXIT_CLEAN, EXIT_FINDINGS, EXIT_TOOL_FAILURE, EXIT_USAGE = 0, 1, 2, 64

DETERMINISTIC_DRIVERS = {"osv-scanner", "semgrep", "dep-scan"}


# --- helpers -------------------------------------------------------------------

def run_cli(target, *extra, path=None, env_extra=None):
    """Run the CLI, returning (returncode, parsed_sarif_or_None, stderr)."""
    env = dict(os.environ)
    if path is not None:
        env["PATH"] = path
    if env_extra:
        env.update(env_extra)
    sarif_path = os.path.join(target, ".scan.sarif") if os.path.isdir(target) else None
    # Write SARIF to a temp file alongside, then read it back.
    import tempfile
    fd, sarif_out = tempfile.mkstemp(suffix=".sarif")
    os.close(fd)
    try:
        proc = subprocess.run(
            [sys.executable, CLI, target, "--sarif", sarif_out, *extra],
            capture_output=True, text=True, env=env, check=False,
        )
        sarif = None
        if os.path.getsize(sarif_out) > 0:
            with open(sarif_out) as fh:
                sarif = json.load(fh)
        return proc.returncode, sarif, proc.stderr
    finally:
        os.unlink(sarif_out)


def fake_path():
    """A PATH containing only the fake tools + the interpreter dir (hermetic)."""
    interp = os.path.dirname(sys.executable)
    return os.pathsep.join([FAKE_TOOLS, interp, "/usr/bin", "/bin"])


_DEP_SCAN_ONLY_DIR = None


def dep_scan_only_path():
    """A PATH with the fake dep-scan tool but NOT osv-scanner/semgrep.

    Isolates dep-scan's own gating behavior: `fake_path()`'s osv-scanner fake
    independently reports a CRITICAL CVE-2020-14343 on any target whose context
    string contains "vulnerable" (see tests/fake-tools/osv-scanner), so a run
    against VULN under the full `fake_path()` always gates regardless of what
    dep-scan reports. Task 002's cached-legacy e2e assertion needs a PATH where
    dep-scan is the only deterministic tool, so its own refusal to gate on an
    unattributed cache sentinel is what determines the exit code.
    """
    global _DEP_SCAN_ONLY_DIR
    if _DEP_SCAN_ONLY_DIR is None:
        import tempfile
        d = tempfile.mkdtemp(prefix="cs-depscan-only-")
        os.symlink(os.path.join(FAKE_TOOLS, "dep-scan"), os.path.join(d, "dep-scan"))
        _DEP_SCAN_ONLY_DIR = d
    interp = os.path.dirname(sys.executable)
    return os.pathsep.join([_DEP_SCAN_ONLY_DIR, interp, "/usr/bin", "/bin"])


_MINIMAL_DIR = None


def minimal_path():
    """A PATH with NO scanner tools at all, for the tool-failure case.

    An isolated dir holding only a `python3` symlink — deliberately NOT the
    interpreter's own dir, because in the container image the scanner tools live
    in /usr/local/bin alongside python3 and would leak in.
    """
    global _MINIMAL_DIR
    if _MINIMAL_DIR is None:
        import tempfile
        d = tempfile.mkdtemp(prefix="cs-nopath-")
        os.symlink(sys.executable, os.path.join(d, "python3"))
        _MINIMAL_DIR = d
    return _MINIMAL_DIR


def all_results(sarif):
    out = []
    for run in sarif.get("runs", []):
        driver = run["tool"]["driver"]["name"]
        tier = run.get("properties", {}).get("codeScannerTier")
        for r in run.get("results", []):
            out.append((driver, tier, r))
    return out


def error_results_from_deterministic(sarif):
    return [
        (driver, r) for driver, tier, r in all_results(sarif)
        if r["level"] == "error" and tier == "deterministic"
    ]


# --- fixtures sanity -----------------------------------------------------------

def test_fixtures_and_cli_exist():
    assert os.access(CLI, os.X_OK), "CLI must be executable"
    assert os.path.isfile(os.path.join(CLEAN, "requirements.txt"))
    assert os.path.isfile(os.path.join(VULN, "requirements.txt"))
    assert os.path.isfile(os.path.join(VULN, "src", "setup_env.sh"))


def test_version():
    proc = subprocess.run([sys.executable, CLI, "--version"],
                          capture_output=True, text=True, check=False)
    assert proc.returncode == 0
    assert proc.stdout.strip() == "code-scanner 1.0.0"


# --- hermetic L5: clean fixture ------------------------------------------------

def test_clean_repo_exits_zero_with_fake_tools():
    rc, sarif, err = run_cli(CLEAN, path=fake_path())
    assert rc == EXIT_CLEAN, f"expected exit 0, got {rc}\n{err}"
    assert sarif is not None
    # No error-level results anywhere (empty / note-only SARIF per TASK-001 L5).
    levels = [r["level"] for _, _, r in all_results(sarif)]
    assert "error" not in levels, f"clean repo must have no error-level results: {levels}"
    # Coverage is still documented: deterministic drivers ran (even with 0 results).
    drivers = {run["tool"]["driver"]["name"] for run in sarif["runs"]}
    assert drivers & DETERMINISTIC_DRIVERS, f"expected deterministic runs, got {drivers}"


# --- hermetic L5: vulnerable fixture -------------------------------------------

def test_vulnerable_repo_exits_nonzero_with_fake_tools():
    rc, sarif, err = run_cli(VULN, path=fake_path())
    assert rc == EXIT_FINDINGS, f"expected exit 1 (findings), got {rc}\n{err}"
    assert sarif is not None


def test_vulnerable_repo_has_error_level_deterministic_result():
    _, sarif, _ = run_cli(VULN, path=fake_path())
    errs = error_results_from_deterministic(sarif)
    assert errs, "expected at least one error-level result from the deterministic tier"
    drivers = {d for d, _ in errs}
    assert drivers & DETERMINISTIC_DRIVERS
    # The gating finding is the known-vulnerable dependency.
    assert any("CVE-2020-14343" in r["ruleId"] or "vulnerability" in r["ruleId"]
               for _, r in errs)


def test_planted_pattern_is_advisory_not_gating():
    """The CRITICAL curl|bash pattern must surface but be tagged best-effort."""
    _, sarif, _ = run_cli(VULN, path=fake_path())
    pattern_results = [
        (tier, r) for driver, tier, r in all_results(sarif)
        if driver == "code-scanner-patterns"
    ]
    assert pattern_results, "planted pattern should be reported"
    assert all(tier == "best-effort" for tier, _ in pattern_results)
    # And its run is marked non-gating.
    for run in sarif["runs"]:
        if run["tool"]["driver"]["name"] == "code-scanner-patterns":
            assert run["properties"]["gating"] is False


def test_gating_excludes_pattern_tier():
    """If we drop the deterministic tools, the CRITICAL pattern alone must NOT gate."""
    # PATH with only the pattern tier available would be a tool-failure (no
    # deterministic tool), so instead point all deterministic fakes at a clean
    # verdict by scanning a copy that has the pattern but no vuln dep.
    import tempfile
    with tempfile.TemporaryDirectory() as tmp:
        target = os.path.join(tmp, "pattern-only")
        shutil.copytree(VULN, target)
        os.remove(os.path.join(target, "requirements.txt"))  # drop the vuln dep
        # Rename so fake tools report clean (no "vulnerable" in path).
        clean_target = os.path.join(tmp, "renamed-clean")
        shutil.move(target, clean_target)
        rc, sarif, err = run_cli(clean_target, path=fake_path())
        # Pattern (CRITICAL, advisory) present but deterministic tier clean → exit 0.
        assert rc == EXIT_CLEAN, f"pattern alone must not gate, got {rc}\n{err}"
        pattern = [r for d, _, r in all_results(sarif) if d == "code-scanner-patterns"]
        assert pattern, "pattern should still be reported as advisory"


# --- threshold behavior --------------------------------------------------------

def test_threshold_critical_only_still_gates_critical_dep():
    rc, _, err = run_cli(VULN, "--severity-threshold", "CRITICAL", path=fake_path())
    assert rc == EXIT_FINDINGS, f"CVSS 9.8 dep should gate at CRITICAL: {err}"


def test_invalid_threshold_is_usage_error():
    rc, _, _ = run_cli(CLEAN, "--severity-threshold", "BOGUS", path=fake_path())
    assert rc == EXIT_USAGE


# --- tool-failure (fail-closed) ------------------------------------------------

def test_no_deterministic_tools_is_tool_failure():
    rc, _, err = run_cli(CLEAN, path=minimal_path())
    assert rc == EXIT_TOOL_FAILURE, f"no tools must fail closed, got {rc}\n{err}"
    assert "no deterministic tool" in err.lower()


def test_nonexistent_target_is_usage_error():
    rc, _, _ = run_cli("/nonexistent/path/xyzzy", path=fake_path())
    assert rc == EXIT_USAGE


# --- SARIF self-validation -----------------------------------------------------

def test_emitted_sarif_validates_for_both_fixtures():
    for target in (CLEAN, VULN):
        _, sarif, _ = run_cli(target, path=fake_path())
        assert sarif is not None
        assert cs.validate_sarif(sarif) == [], f"{target} emitted invalid SARIF"
        assert sarif["version"] == "2.1.0"


def test_built_sarif_validates():
    findings = [
        cs.Finding("CVE-2099-1", "CRITICAL", "boom", "osv-scanner",
                   cs.TIER_DETERMINISTIC, path="requirements.txt"),
        cs.Finding("pattern/x", "HIGH", "curl|bash", "code-scanner-patterns",
                   cs.TIER_BEST_EFFORT, path="x.sh", line=3),
    ]
    sarif = cs.build_sarif(findings, REPO,
                           ran=[("osv-scanner", cs.TIER_DETERMINISTIC),
                                ("code-scanner-patterns", cs.TIER_BEST_EFFORT)])
    assert cs.validate_sarif(sarif) == []


def test_validator_catches_malformed():
    bad = {
        "version": "1.0.0",  # wrong version
        "runs": [{
            "tool": {"driver": {"name": ""}},        # empty driver name
            "results": [
                {"ruleId": "", "level": "fatal",      # bad ruleId + bad level
                 "message": {}},                       # missing message.text
            ],
        }],
    }
    problems = cs.validate_sarif(bad)
    assert any("version" in p for p in problems)
    assert any("driver.name" in p for p in problems)
    assert any("ruleId" in p for p in problems)
    assert any("level" in p for p in problems)
    assert any("message.text" in p for p in problems)


def test_validator_accepts_empty_runs():
    assert cs.validate_sarif({"version": "2.1.0", "runs": []}) == []


# --- semgrep ruleset resolution ------------------------------------------------

def test_semgrep_config_defaults_to_bundled_offline_rules():
    cs.SEMGREP_CONFIG_OVERRIDE = None
    os.environ.pop("CODE_SCANNER_SEMGREP_CONFIG", None)
    cfg = cs._semgrep_config()
    assert cfg.endswith(os.path.join("cli", "semgrep-rules"))
    assert os.path.isdir(cfg)
    rule_files = [f for f in os.listdir(cfg) if f.endswith((".yaml", ".yml"))]
    assert rule_files, "bundled ruleset dir must contain rule files"
    assert cfg != "auto", "must not default to networked --config auto"


def test_semgrep_config_override_precedence():
    try:
        cs.SEMGREP_CONFIG_OVERRIDE = "p/ci"
        assert cs._semgrep_config() == "p/ci"
        cs.SEMGREP_CONFIG_OVERRIDE = None
        os.environ["CODE_SCANNER_SEMGREP_CONFIG"] = "/tmp/myrules"
        assert cs._semgrep_config() == "/tmp/myrules"
    finally:
        cs.SEMGREP_CONFIG_OVERRIDE = None
        os.environ.pop("CODE_SCANNER_SEMGREP_CONFIG", None)


def test_bundled_semgrep_rules_are_valid_yaml():
    import importlib.util as _u
    if _u.find_spec("yaml") is None:
        pytest.skip("PyYAML not available to validate rule syntax")
    import yaml
    rules_dir = os.path.join(REPO, "cli", "semgrep-rules")
    for fn in os.listdir(rules_dir):
        if not fn.endswith((".yaml", ".yml")):
            continue
        with open(os.path.join(rules_dir, fn)) as fh:
            doc = yaml.safe_load(fh)
        assert isinstance(doc.get("rules"), list) and doc["rules"], fn
        for r in doc["rules"]:
            assert r.get("id") and r.get("languages") and r.get("severity"), fn


# --- dep-scan `--format json` contract (task 001) -------------------------------
# Pins the documented, stable contract (`dep-scan check ... --format json`) that
# replaced the deprecated `--json` alias. See docs/tasks/backlog/001-*.md and its
# paired test spec for the full rationale.

SCAN_COMMANDS_MD = os.path.join(REPO, "code-scanner", "references",
                                 "scan-commands.md")
FAKE_DEP_SCAN = os.path.join(FAKE_TOOLS, "dep-scan")
_JSON_FLAG = re.compile(r"--json\b")

# --- dep-scan cached-verdict attribution + shared version pin (task 002) -------
# dep-scan task 112 shape: real version, full policies, additive `cache` object.
# Provenance key confirmed against dep-scan's docs/spec/interfaces.md (task 112,
# merged): a nested `cache` object (`cache.hit` / `cache.scanned_at` /
# `cache.dep_scan_version`), not a flat string field. Gating must not read it.

def _attributed_cached_entry():
    return {
        "package": "PyYAML", "version": "5.3.1", "registry": "pypi",
        "age_hours": None, "result": "block",
        "reason": "Found known vulnerability(ies): GHSA-8q59-q68h-6hv4",
        "cache": {"hit": True, "scanned_at": "2026-07-10T08:15:00Z",
                  "dep_scan_version": "1.3.1"},
        "policies": [
            {"policy_name": "age", "result": "pass", "reason": None},
            {"policy_name": "vulnerability", "result": "block",
             "reason": "Found known vulnerability(ies): GHSA-8q59-q68h-6hv4"},
        ],
    }


def _legacy_sentinel_entry():
    return {"package": "PyYAML", "version": "cached", "registry": "pypi",
            "age_hours": None, "result": "block", "reason": "cached result",
            "policies": []}


def _write_pyyaml_manifest(tmp_path):
    """A single-package pypi lockfile-mode manifest (the spec's shared fixture)."""
    manifest = tmp_path / "requirements.txt"
    manifest.write_text("pyyaml==5.3.1\n")
    return manifest


class _RecordingRun:
    """Stub for cs._run: records every cmd, returns a canned (rc, stdout, stderr)."""

    def __init__(self, rc, stdout, stderr=""):
        self.rc = rc
        self.stdout = stdout
        self.stderr = stderr
        self.calls = []

    def __call__(self, cmd, cwd=None):
        self.calls.append(cmd)
        return self.rc, self.stdout, self.stderr


def _patch_dep_scan_only(monkeypatch):
    monkeypatch.setattr(cs, "_have", lambda tool: tool == "dep-scan")


def test_deprecated_json_flag_gone_documented_flag_present():
    """T-001-01."""
    cli_text = open(CLI, encoding="utf-8").read()
    scan_commands_text = open(SCAN_COMMANDS_MD, encoding="utf-8").read()

    assert not _JSON_FLAG.search(cli_text), \
        "cli/code-scanner must not invoke dep-scan with the deprecated --json flag"
    assert not _JSON_FLAG.search(scan_commands_text), \
        "scan-commands.md must not document the deprecated --json flag"
    assert cli_text.count('"--format", "json"') >= 2
    assert len(re.findall(r"dep-scan check[^\n]*--format json",
                           scan_commands_text)) >= 6


def test_run_dep_scan_command_shape_lockfile_mode(tmp_path, monkeypatch):
    """T-001-02."""
    manifest = _write_pyyaml_manifest(tmp_path)
    _patch_dep_scan_only(monkeypatch)
    stub = _RecordingRun(0, "[]", "")
    monkeypatch.setattr(cs, "_run", stub)

    result = cs.run_dep_scan(str(tmp_path))

    assert stub.calls == [
        ["dep-scan", "check", "--lockfile", str(manifest),
         "--lockfile-type", "pypi", "--format", "json"]
    ]
    assert result == []


def test_run_dep_scan_command_shape_name_mode(tmp_path, monkeypatch):
    """T-001-03."""
    pkg = tmp_path / "package.json"
    pkg.write_text(json.dumps({"dependencies": {"left-pad": "^1.0.0"}}))
    _patch_dep_scan_only(monkeypatch)
    stub = _RecordingRun(0, "[]", "")
    monkeypatch.setattr(cs, "_run", stub)

    cs.run_dep_scan(str(tmp_path))

    assert stub.calls == [
        ["dep-scan", "check", "left-pad", "--registry", "npm", "--format", "json"]
    ]


def test_fake_dep_scan_rejects_deprecated_json_flag(tmp_path):
    """T-001-04."""
    clean_cwd = tmp_path / "clean-target"
    clean_cwd.mkdir()

    ok = subprocess.run(
        [sys.executable, FAKE_DEP_SCAN, "check", "--lockfile", "x",
         "--lockfile-type", "pypi", "--format", "json"],
        cwd=str(clean_cwd), capture_output=True, text=True, check=False,
    )
    assert ok.returncode == 0
    assert json.loads(ok.stdout) == []

    rejected = subprocess.run(
        [sys.executable, FAKE_DEP_SCAN, "check", "--lockfile", "x",
         "--lockfile-type", "pypi", "--json"],
        cwd=str(clean_cwd), capture_output=True, text=True, check=False,
    )
    assert rejected.returncode == 2
    assert rejected.stdout == ""
    assert "--json" in rejected.stderr


def test_dep_scan_entries_bare_array_passes_through():
    """T-001-05."""
    data = [{"package": "a"}, {"package": "b"}]
    assert cs._dep_scan_entries(data) == data


def test_dep_scan_entries_transitive_shape_unwraps_results():
    """T-001-06."""
    data = {"results": [{"package": "a"}],
            "transitive": {"worst_verdict": "block", "diagnostics": [], "nodes": []}}
    assert cs._dep_scan_entries(data) == [{"package": "a"}]


@pytest.mark.parametrize("bad", ["oops", 42, None, {"no_results_key": 1}])
def test_dep_scan_entries_unknown_shapes_yield_empty_list(bad):
    """T-001-07."""
    assert cs._dep_scan_entries(bad) == []


def test_run_dep_scan_per_policy_mapping_mixed(tmp_path, monkeypatch):
    """T-001-08."""
    _write_pyyaml_manifest(tmp_path)
    _patch_dep_scan_only(monkeypatch)
    entry = {
        "package": "PyYAML", "version": "5.3.1", "registry": "pypi",
        "age_hours": 40000, "result": "block",
        "reason": "Found known vulnerability(ies): GHSA-8q59-q68h-6hv4",
        "policies": [
            {"policy_name": "age", "result": "pass", "reason": None},
            {"policy_name": "typosquatting", "result": "warn",
             "reason": "similar to 'pyaml'"},
            {"policy_name": "vulnerability", "result": "block",
             "reason": "Found known vulnerability(ies): GHSA-8q59-q68h-6hv4"},
        ],
    }
    stub = _RecordingRun(1, json.dumps([entry]), "")
    monkeypatch.setattr(cs, "_run", stub)

    findings = cs.run_dep_scan(str(tmp_path))

    assert len(findings) == 2
    by_rule = {f.rule_id: f for f in findings}

    typo = by_rule["dep-scan/typosquatting"]
    assert typo.severity == "MEDIUM"
    assert typo.message == "PyYAML@5.3.1: similar to 'pyaml'"
    assert typo.driver == "dep-scan"
    assert typo.tier == cs.TIER_DETERMINISTIC
    assert typo.path.endswith("requirements.txt")

    vuln = by_rule["dep-scan/vulnerability"]
    assert vuln.severity == "HIGH"
    assert ("PyYAML@5.3.1: Found known vulnerability(ies): GHSA-8q59-q68h-6hv4"
            in vuln.message)
    assert vuln.path.endswith("requirements.txt")


def test_run_dep_scan_warm_cache_sentinel_does_not_gate(tmp_path, monkeypatch, capsys):
    """T-001-09 (superseded by task 002: legacy-note wording, same zero-findings
    expectation; see T-002-03 for the dedicated task 002 assertion)."""
    _write_pyyaml_manifest(tmp_path)
    _patch_dep_scan_only(monkeypatch)
    entry = {
        "package": "PyYAML", "version": "cached", "registry": "pypi",
        "age_hours": None, "result": "block", "reason": "cached result",
        "policies": [],
    }
    stub = _RecordingRun(1, json.dumps([entry]), "")
    monkeypatch.setattr(cs, "_run", stub)

    findings = cs.run_dep_scan(str(tmp_path))

    assert findings == []
    err = capsys.readouterr().err
    assert "unattributable" in err
    assert "legacy" in err
    assert "not gating" in err


def test_run_dep_scan_unparseable_stdout_raises_tool_error(tmp_path, monkeypatch):
    """T-001-10."""
    _write_pyyaml_manifest(tmp_path)
    _patch_dep_scan_only(monkeypatch)
    stub = _RecordingRun(1, "not json {", "")
    monkeypatch.setattr(cs, "_run", stub)

    with pytest.raises(cs.ToolError, match="unparseable JSON"):
        cs.run_dep_scan(str(tmp_path))


def test_run_dep_scan_rc2_empty_stdout_raises_tool_error(tmp_path, monkeypatch):
    """T-001-11."""
    _write_pyyaml_manifest(tmp_path)
    _patch_dep_scan_only(monkeypatch)
    stub = _RecordingRun(2, "", "boom: config invalid")
    monkeypatch.setattr(cs, "_run", stub)

    with pytest.raises(cs.ToolError, match=r"rc=2"):
        cs.run_dep_scan(str(tmp_path))


def test_run_dep_scan_rc1_with_parseable_output_is_not_a_failure(tmp_path, monkeypatch):
    """T-001-11 (counter-case)."""
    _write_pyyaml_manifest(tmp_path)
    _patch_dep_scan_only(monkeypatch)
    stub = _RecordingRun(1, "[]", "")
    monkeypatch.setattr(cs, "_run", stub)

    assert cs.run_dep_scan(str(tmp_path)) == []


def test_attributed_cached_block_gates_high(tmp_path, monkeypatch, capsys):
    """T-002-01: attributed cached block gates as HIGH."""
    _write_pyyaml_manifest(tmp_path)
    _patch_dep_scan_only(monkeypatch)
    stub = _RecordingRun(1, json.dumps([_attributed_cached_entry()]), "")
    monkeypatch.setattr(cs, "_run", stub)

    findings = cs.run_dep_scan(str(tmp_path))

    assert len(findings) == 1
    f = findings[0]
    assert f.rule_id == "dep-scan/vulnerability"
    assert f.severity == "HIGH"
    assert f.message == ("PyYAML@5.3.1: Found known vulnerability(ies): "
                          "GHSA-8q59-q68h-6hv4")
    assert f.tier == cs.TIER_DETERMINISTIC
    err = capsys.readouterr().err
    assert "not gating" not in err


def test_gating_is_provenance_field_agnostic(tmp_path, monkeypatch, capsys):
    """T-002-02: same entry minus the `cache` key yields identical findings."""
    _write_pyyaml_manifest(tmp_path)
    _patch_dep_scan_only(monkeypatch)
    entry = _attributed_cached_entry()
    del entry["cache"]
    stub = _RecordingRun(1, json.dumps([entry]), "")
    monkeypatch.setattr(cs, "_run", stub)

    findings = cs.run_dep_scan(str(tmp_path))

    assert len(findings) == 1
    f = findings[0]
    assert f.rule_id == "dep-scan/vulnerability"
    assert f.severity == "HIGH"
    assert f.message == ("PyYAML@5.3.1: Found known vulnerability(ies): "
                          "GHSA-8q59-q68h-6hv4")
    assert f.tier == cs.TIER_DETERMINISTIC
    err = capsys.readouterr().err
    assert "not gating" not in err


def test_legacy_sentinel_still_refuses_to_gate(tmp_path, monkeypatch, capsys):
    """T-002-03."""
    _write_pyyaml_manifest(tmp_path)
    _patch_dep_scan_only(monkeypatch)
    stub = _RecordingRun(1, json.dumps([_legacy_sentinel_entry()]), "")
    monkeypatch.setattr(cs, "_run", stub)

    findings = cs.run_dep_scan(str(tmp_path))

    assert findings == []
    err = capsys.readouterr().err
    assert "legacy" in err
    assert "PyYAML" in err
    assert "not gating" in err


def test_attributed_cached_warn_maps_to_medium(tmp_path, monkeypatch):
    """T-002-04."""
    _write_pyyaml_manifest(tmp_path)
    _patch_dep_scan_only(monkeypatch)
    entry = _attributed_cached_entry()
    entry["result"] = "warn"
    entry["policies"] = [
        {"policy_name": "age", "result": "pass", "reason": None},
        {"policy_name": "typosquatting", "result": "warn",
         "reason": "similar to 'pyaml'"},
    ]
    stub = _RecordingRun(1, json.dumps([entry]), "")
    monkeypatch.setattr(cs, "_run", stub)

    findings = cs.run_dep_scan(str(tmp_path))

    assert len(findings) == 1
    f = findings[0]
    assert f.severity == "MEDIUM"
    assert f.rule_id == "dep-scan/typosquatting"
    assert f.message == "PyYAML@5.3.1: similar to 'pyaml'"


@pytest.mark.parametrize("order", ["attributed-first", "legacy-first"])
def test_mixed_batch_gates_only_attributed_entry(order, tmp_path, monkeypatch, capsys):
    """T-002-05."""
    _write_pyyaml_manifest(tmp_path)
    _patch_dep_scan_only(monkeypatch)
    attributed = _attributed_cached_entry()
    legacy = _legacy_sentinel_entry()
    batch = [attributed, legacy] if order == "attributed-first" else [legacy, attributed]
    stub = _RecordingRun(1, json.dumps(batch), "")
    monkeypatch.setattr(cs, "_run", stub)

    findings = cs.run_dep_scan(str(tmp_path))

    assert len(findings) == 1
    assert findings[0].rule_id == "dep-scan/vulnerability"
    assert findings[0].severity == "HIGH"
    err = capsys.readouterr().err
    assert err.count("legacy") == 1


def test_end_to_end_exit_codes_preserved_0_1_2_64():
    """T-001-12: the explicit non-regression gate for the flag switch."""
    rc, _, err = run_cli(CLEAN, path=fake_path())
    assert rc == EXIT_CLEAN, f"expected 0 (clean), got {rc}\n{err}"

    rc, sarif, err = run_cli(VULN, path=fake_path())
    assert rc == EXIT_FINDINGS, f"expected 1 (findings), got {rc}\n{err}"
    errs = error_results_from_deterministic(sarif)
    assert any(r["ruleId"] == "dep-scan/vulnerability" for _, r in errs), \
        "expected an error-level dep-scan/vulnerability result from the fake's block policy"

    rc, _, err = run_cli(CLEAN, path=minimal_path())
    assert rc == EXIT_TOOL_FAILURE, f"expected 2 (no deterministic tools), got {rc}\n{err}"

    rc, _, err = run_cli(CLEAN, "--severity-threshold", "BOGUS", path=fake_path())
    assert rc == EXIT_USAGE, f"expected 64 (usage), got {rc}\n{err}"


def test_e2e_cached_attributed_mode_exits_1():
    """T-002-06."""
    rc, sarif, err = run_cli(VULN, path=fake_path(),
                              env_extra={"FAKE_DEPSCAN_MODE": "cached-attributed"})
    assert rc == EXIT_FINDINGS, f"expected 1 (attributed cached block gates), got {rc}\n{err}"
    dep_scan_errs = [
        r for run in sarif["runs"] if run["tool"]["driver"]["name"] == "dep-scan"
        for r in run.get("results", [])
        if r["level"] == "error" and r["ruleId"] == "dep-scan/vulnerability"
    ]
    assert dep_scan_errs, f"expected an error-level dep-scan/vulnerability result: {sarif}"
    dep_scan_runs = [run for run in sarif["runs"]
                      if run["tool"]["driver"]["name"] == "dep-scan"]
    assert all(run["properties"]["gating"] is True for run in dep_scan_runs)


def test_e2e_cached_legacy_mode_exits_0_and_warns():
    """T-002-07: the load-bearing fail-closed assertion. A top-level `block`
    without policy attribution must not flip the exit code. Uses
    dep_scan_only_path() (not fake_path()) so osv-scanner's independent,
    mode-agnostic CVE finding on the VULN fixture can't ride along and mask a
    regression in dep-scan's own refusal-to-gate logic."""
    rc, sarif, err = run_cli(VULN, path=dep_scan_only_path(),
                              env_extra={"FAKE_DEPSCAN_MODE": "cached-legacy"})
    assert rc == EXIT_CLEAN, f"expected 0 (legacy sentinel must not gate), got {rc}\n{err}"
    assert "legacy" in err
    dep_scan_errs = [
        r for run in sarif["runs"] if run["tool"]["driver"]["name"] == "dep-scan"
        for r in run.get("results", [])
        if r["level"] == "error"
    ]
    assert dep_scan_errs == [], f"expected zero error-level dep-scan results: {dep_scan_errs}"


@pytest.mark.parametrize("mode,expected_version,expected_policies_empty", [
    ("cached-attributed", "5.3.1", False),
    ("cached-legacy", "cached", True),
])
def test_fake_dep_scan_modes_are_pinned(mode, expected_version, expected_policies_empty):
    """T-002-08."""
    target_dir = os.path.join(FIXTURES, "vulnerable-repo")
    env = dict(os.environ)
    env["FAKE_DEPSCAN_MODE"] = mode
    proc = subprocess.run(
        [sys.executable, FAKE_DEP_SCAN, "check", "--lockfile", "requirements.txt",
         "--lockfile-type", "pypi", "--format", "json"],
        cwd=target_dir, capture_output=True, text=True, env=env, check=False,
    )
    entries = json.loads(proc.stdout)
    assert len(entries) == 1
    assert entries[0]["version"] == expected_version
    assert (entries[0]["policies"] == []) == expected_policies_empty


def test_fake_dep_scan_default_mode_shape_unchanged():
    """T-002-08 (regression counter-case): unset mode keeps the pre-task-002 shape."""
    target_dir = os.path.join(FIXTURES, "vulnerable-repo")
    proc = subprocess.run(
        [sys.executable, FAKE_DEP_SCAN, "check", "--lockfile", "requirements.txt",
         "--lockfile-type", "pypi", "--format", "json"],
        cwd=target_dir, capture_output=True, text=True, check=False,
    )
    entries = json.loads(proc.stdout)
    assert len(entries) == 1
    assert entries[0]["version"] == "5.3.1"
    assert "cache" not in entries[0]
    assert entries[0]["policies"]


# --- dep-scan Dockerfile: shared PINNED_VERSION pin (task 002 part b) ----------

DEP_SCAN_DOCKERFILE = os.path.join(REPO, "code-scanner", "docker",
                                    "Dockerfile.dep-scan")
_INDEPENDENT_PIN = re.compile(r'VERSION="v[0-9]')


def test_dockerfile_static_contract():
    """T-002-09."""
    text = open(DEP_SCAN_DOCKERFILE, encoding="utf-8").read()
    assert not _INDEPENDENT_PIN.search(text), \
        "Dockerfile.dep-scan must not hardcode an independent VERSION literal"
    assert "PINNED_VERSION" in text
    assert "ARG DEP_SCAN_VERSION" in text
    assert 'test -n "$VERSION"' in text
    assert re.search(r"dep-scan --version\s*\|\s*grep\b", text), \
        "expected a build-time `dep-scan --version | grep ...` verification step"


DOCKER = shutil.which("docker")
_KNOWN_GOOD_PIN = "v1.3.1"


@pytest.mark.skipif(not DOCKER, reason="docker not available")
def test_docker_build_with_build_arg_pins_version():
    """T-002-10: deterministic positive build via --build-arg."""
    tag = "dep-scan:t002-positive"
    build = subprocess.run(
        [DOCKER, "build", "-f", DEP_SCAN_DOCKERFILE,
         "--build-arg", f"DEP_SCAN_VERSION={_KNOWN_GOOD_PIN}", "-t", tag, REPO],
        capture_output=True, text=True, check=False,
    )
    assert build.returncode == 0, f"build failed:\n{build.stdout}\n{build.stderr}"
    try:
        run = subprocess.run(
            [DOCKER, "run", "--rm", "--entrypoint", "dep-scan", tag, "--version"],
            capture_output=True, text=True, check=False,
        )
        assert run.returncode == 0, run.stderr
        assert _KNOWN_GOOD_PIN[1:] in run.stdout, run.stdout
    finally:
        subprocess.run([DOCKER, "rmi", "-f", tag], capture_output=True, check=False)


@pytest.mark.skipif(not DOCKER, reason="docker not available")
def test_docker_build_bogus_version_fails_closed():
    """T-002-11: a bogus version must fail the build, not fall through unpinned."""
    tag = "dep-scan:t002-bogus"
    build = subprocess.run(
        [DOCKER, "build", "-f", DEP_SCAN_DOCKERFILE,
         "--build-arg", "DEP_SCAN_VERSION=v0.0.0", "-t", tag, REPO],
        capture_output=True, text=True, check=False,
    )
    assert build.returncode != 0, "build must fail closed on a nonexistent release"
    subprocess.run([DOCKER, "rmi", "-f", tag], capture_output=True, check=False)


# --- comment/caveat hygiene (task 002) ------------------------------------------

def test_stale_cache_caveat_text_updated():
    """T-002-13. The stale phrase is built via concatenation so this assertion's
    own source line is not itself a false-positive match."""
    cli_text = open(CLI, encoding="utf-8").read()
    test_text = open(os.path.abspath(__file__), encoding="utf-8").read()
    stale_phrase = "unattributable " + "cached result" + " sentinel"
    assert "likely a cache hit" not in cli_text
    assert "legacy" in cli_text
    assert stale_phrase not in test_text


# --- opt-in real-tools integration ---------------------------------------------

REAL = os.environ.get("CODE_SCANNER_REAL_TOOLS") == "1"


@pytest.mark.skipif(not REAL, reason="set CODE_SCANNER_REAL_TOOLS=1 to run")
def test_real_tools_clean_repo():
    if not any(shutil.which(t) for t in DETERMINISTIC_DRIVERS):
        pytest.skip("no real deterministic tool on PATH")
    rc, sarif, err = run_cli(CLEAN)
    assert rc == EXIT_CLEAN, f"real-tools clean repo expected 0, got {rc}\n{err}"


@pytest.mark.skipif(not REAL, reason="set CODE_SCANNER_REAL_TOOLS=1 to run")
def test_real_tools_vulnerable_repo():
    # The gating assertion is a version-specific CVE. dep-scan's cache is now
    # attributed on a hit (task 112: real version, full policies), so a warm
    # cache no longer drops the finding out of gating. A *cold* run still
    # depends on live registry/OSV lookups, though, which are not reproducible
    # across arbitrary CI environments. OSV-Scanner reads pinned versions
    # directly from the lockfile and is cache-stable regardless of network
    # state, so it stays the required tool for this strict, deterministic
    # assertion.
    if not shutil.which("osv-scanner"):
        pytest.skip("strict vuln-dep gating needs osv-scanner (cache-stable, "
                    "version-aware, and reproducible without a live registry "
                    "round-trip)")
    rc, sarif, err = run_cli(VULN)
    assert rc == EXIT_FINDINGS, f"real-tools vuln repo expected 1, got {rc}\n{err}"
    assert error_results_from_deterministic(sarif), \
        "expected a real error-level deterministic finding for pyyaml CVE"
