# Test Spec 003: Archive completed backlog tasks 001 and 002

**Linked task:** [`docs/tasks/backlog/003-archive-completed-backlog-tasks.md`](../backlog/003-archive-completed-backlog-tasks.md)
**Written:** 2026-10-31
**Status:** ready for implementation

## Requirements coverage

| Req ID | Description | Test cases |
|--------|-------------|------------|
| REQ-003-01 | Tasks 001, 002, and 003 live in `docs/tasks/completed/` with completed status. | TC-003-01 |
| REQ-003-02 | `docs/tasks/backlog/` contains no `.md` files. | TC-003-02 |
| REQ-003-03 | `docs/tasks/test-specs/coverage-tracker.md` documents tasks 001, 002, and 003. | TC-003-03 |
| REQ-003-04 | Gate CLI unit test suite passes. | TC-003-04 |

## Test cases

### TC-003-01: Completed tasks archived in `docs/tasks/completed/`

- **Requirement:** REQ-003-01
- **Level:** L2 (test assertion in `tests/test_gate_cli.py`)
- **Step:** Assert `docs/tasks/completed/001-depscan-json-contract.md`, `002-gate-cached-verdicts-and-shared-pin.md`, and `003-archive-completed-backlog-tasks.md` exist on disk.

### TC-003-02: `docs/tasks/backlog/` is empty of `.md` files

- **Requirement:** REQ-003-02
- **Level:** L2 (test assertion in `tests/test_gate_cli.py`)
- **Step:** Assert no `*.md` files remain under `docs/tasks/backlog/`.

### TC-003-03: `coverage-tracker.md` present and populated

- **Requirement:** REQ-003-03
- **Level:** L2 (test assertion in `tests/test_gate_cli.py`)
- **Step:** Assert `docs/tasks/test-specs/coverage-tracker.md` exists and references `001-depscan-json-contract-test-spec.md`, `002-gate-cached-verdicts-and-shared-pin-test-spec.md`, and `003-archive-completed-backlog-tasks-test-spec.md`.

### TC-003-04: Full test suite passes

- **Requirement:** REQ-003-04
- **Level:** L2
- **Step:** Run `python3 -m unittest discover -s tests -v` and verify `OK`.
