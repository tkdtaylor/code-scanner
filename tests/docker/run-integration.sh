#!/usr/bin/env bash
# Build the integration-test runner image and run the real-tools suite inside it.
#
# The container provisions osv-scanner / semgrep / dep-scan natively (ADR-002) and
# runs pytest with CODE_SCANNER_REAL_TOOLS=1 against the repo, mounted read-only.
# Needs outbound network (OSV API, npm/PyPI/crates/go registries, semgrep.dev).
#
# Usage:
#   tests/docker/run-integration.sh                # build + run the whole suite
#   tests/docker/run-integration.sh -k real        # pass extra args through to pytest
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
IMAGE="code-scanner-itest"
ENGINE="${CONTAINER_ENGINE:-docker}"

echo ">> Building ${IMAGE} (${ENGINE})..."
"${ENGINE}" build -t "${IMAGE}" -f "${REPO_ROOT}/tests/docker/Dockerfile" \
  "${REPO_ROOT}/tests/docker"

echo ">> Running integration suite..."
exec "${ENGINE}" run --rm \
  -v "${REPO_ROOT}:/repo:ro" \
  "${IMAGE}" \
  python3 -m pytest tests/test_gate_cli.py -v "$@"
