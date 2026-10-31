# Task 003: Archive completed backlog tasks 001 and 002

**Project:** code-scanner
**Created:** 2026-10-31
**Status:** ready

## Goal

Move completed task files `001-depscan-json-contract.md` and `002-gate-cached-verdicts-and-shared-pin.md` from `docs/tasks/backlog/` into `docs/tasks/completed/` and create `docs/tasks/test-specs/coverage-tracker.md` so the repository task layout matches the completed implementation on `main`.

## Context

Commits `57ec92a` and `eedf4cc` implemented and merged tasks 001 and 002 on `main`, but the task files remained in `docs/tasks/backlog/` and no `docs/tasks/completed/` directory or `coverage-tracker.md` was created.

## Requirements

| Req ID | Description | Priority |
|--------|-------------|----------|
| REQ-003-01 | `001-depscan-json-contract.md` and `002-gate-cached-verdicts-and-shared-pin.md` are moved with `git mv` to `docs/tasks/completed/` and updated with `**Status:** completed`. | must have |
| REQ-003-02 | `docs/tasks/backlog/` contains no stale completed task files (only `.gitkeep`). | must have |
| REQ-003-03 | `docs/tasks/test-specs/coverage-tracker.md` tracks tasks 001, 002, and 003 with their paired test specs and verification evidence. | must have |
| REQ-003-04 | Existing gate CLI test suite (`python3 -m unittest discover -s tests -v`) passes without regression. | must have |

## Readiness gate

- [x] Test spec `docs/tasks/test-specs/003-archive-completed-backlog-tasks-test-spec.md` exists
- [x] Tasks 001 and 002 are already implemented on `main`

## Implementation outline

1. Create branch `task/003-archive-completed-backlog-tasks`.
2. Create `docs/tasks/completed/` and `git mv` `001-depscan-json-contract.md`, `002-gate-cached-verdicts-and-shared-pin.md`, and `003-archive-completed-backlog-tasks.md` into `docs/tasks/completed/`, adding `docs/tasks/backlog/.gitkeep`.
3. Update `**Status:** completed` in the moved task files.
4. Create `docs/tasks/test-specs/coverage-tracker.md` recording tasks 001, 002, and 003.
5. Run `python3 -m unittest discover -s tests -v` to confirm all tests pass.

## Acceptance criteria

- [ ] [REQ-003-01] TC-003-01: Tasks 001, 002, and 003 reside under `docs/tasks/completed/`.
- [ ] [REQ-003-02] TC-003-02: `docs/tasks/backlog/` has no `.md` task files.
- [ ] [REQ-003-03] TC-003-03: `docs/tasks/test-specs/coverage-tracker.md` exists and lists tasks 001, 002, and 003.
- [ ] [REQ-003-04] TC-003-04: `python3 -m unittest discover -s tests -v` exits 0.

## Verification plan

- **Highest level achievable:** L2/L3 test suite + file layout check.
- **Command:** `python3 -m unittest discover -s tests -v`
