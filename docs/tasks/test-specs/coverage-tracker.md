# Test Coverage Tracker

**Project:** code-scanner

## Rules

- Test specs are written **before** implementation begins: no exceptions
- A task is only "complete" when all its test cases pass
- Each row maps a task ID to its spec file and current test status

## Coverage

| Task ID | Feature | Spec file | Tests written | Status |
|---------|---------|-----------|---------------|--------|
| 001 | Consume dep-scan via documented `--format json` contract | 001-depscan-json-contract-test-spec.md | 12/12 (T-001-01..12) | ✅ (commit 138a411; 58 passed, 2 skipped in pytest) |
| 002 | Gate on attributed cached verdicts; shared PINNED_VERSION pin | 002-gate-cached-verdicts-and-shared-pin-test-spec.md | 13/13 (T-002-01..13) | ✅ (commit 5450b8d; 58 passed, 2 skipped in pytest) |
| 003 | Archive completed backlog tasks 001 and 002 | 003-archive-completed-backlog-tasks-test-spec.md | 4/4 (TC-003-01..04) | ✅ (commit ffc4608; 4 passed in unittest, 62 passed, 2 skipped in pytest) |

## Verification evidence

### Task 003: Archive completed backlog tasks 001 and 002

Command: `python3 -m unittest discover -s tests -v`

```
test_tc_003_01_completed_tasks_archived (test_gate_cli.TestTask003ArchivedBacklog.test_tc_003_01_completed_tasks_archived)
TC-003-01: Tasks 001, 002, and 003 live in docs/tasks/completed/. ... ok
test_tc_003_02_backlog_empty_of_markdown_files (test_gate_cli.TestTask003ArchivedBacklog.test_tc_003_02_backlog_empty_of_markdown_files)
TC-003-02: docs/tasks/backlog/ contains no .md files. ... ok
test_tc_003_03_coverage_tracker_references_specs (test_gate_cli.TestTask003ArchivedBacklog.test_tc_003_03_coverage_tracker_references_specs)
TC-003-03: coverage-tracker.md documents tasks 001, 002, and 003. ... ok
test_tc_003_04_test_suite_passes (test_gate_cli.TestTask003ArchivedBacklog.test_tc_003_04_test_suite_passes)
TC-003-04: Gate CLI unit test suite execution contract. ... ok

----------------------------------------------------------------------
Ran 4 tests in 0.000s

OK
```

## Status key

| Symbol | Meaning |
|--------|---------|
| ✅ | Done |
| 🟡 | In progress / verification pending |
| ⏳ | In progress |
| ❌ | Not started |
| ⚠️ | Blocked |
