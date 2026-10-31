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
| 003 | Archive completed backlog tasks 001 and 002 | 003-archive-completed-backlog-tasks-test-spec.md | 4/4 (TC-003-01..04) | 🟡 |

## Status key

| Symbol | Meaning |
|--------|---------|
| ✅ | Done |
| 🟡 | In progress / verification pending |
| ⏳ | In progress |
| ❌ | Not started |
| ⚠️ | Blocked |
