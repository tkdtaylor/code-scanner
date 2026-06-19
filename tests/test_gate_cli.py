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
    # The gating assertion is a version-specific CVE. OSV-Scanner reads pinned
    # versions directly and is cache-stable; dep-scan's on-disk cache can collapse
    # a real verdict into an unattributable "cached result" sentinel (which we
    # deliberately do NOT gate on), so dep-scan alone can't make this assertion
    # reproducible. Require osv-scanner for the strict check.
    if not shutil.which("osv-scanner"):
        pytest.skip("strict vuln-dep gating needs osv-scanner (cache-stable, "
                    "version-aware); dep-scan's cache is non-deterministic here")
    rc, sarif, err = run_cli(VULN)
    assert rc == EXIT_FINDINGS, f"real-tools vuln repo expected 1, got {rc}\n{err}"
    assert error_results_from_deterministic(sarif), \
        "expected a real error-level deterministic finding for pyyaml CVE"
