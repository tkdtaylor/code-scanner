# Reproducible runner image for the code-scanner gate-mode integration tests.
#
# Provisions the three deterministic-tier tools on PATH — osv-scanner, semgrep,
# dep-scan — exactly the way a real gate-tools dir would (ADR-002, socket-less
# native binaries). No Docker/Podman socket is used or needed inside here; this
# image just runs the native tools + pytest against the repo (mounted at /repo).
#
# Build:  docker build -t code-scanner-itest -f tests/docker/Dockerfile tests/docker
# Run:    see tests/docker/run-integration.sh
#
# Versions are pinned so the gate toolchain is reproducible (REQ-008). Bump them
# here in lockstep with code-scanner/docker/Dockerfile.dep-scan.

# --- stage 1: build osv-scanner from source (avoids release-asset name drift) --
FROM golang:1.24-bookworm AS osv
ARG OSV_SCANNER_VERSION=v2.0.2
RUN go install github.com/google/osv-scanner/v2/cmd/osv-scanner@${OSV_SCANNER_VERSION}
# binary lands at /go/bin/osv-scanner

# --- stage 2: the runner --------------------------------------------------------
FROM python:3.12-slim

ARG DEP_SCAN_VERSION=""
ARG SEMGREP_VERSION=1.97.0

RUN apt-get update && apt-get install -y --no-install-recommends \
      ca-certificates curl git \
    && rm -rf /var/lib/apt/lists/*

# osv-scanner (from the build stage)
COPY --from=osv /go/bin/osv-scanner /usr/local/bin/osv-scanner

# dep-scan — pinned release binary (same install.sh channel as Dockerfile.dep-scan)
RUN VERSION="${DEP_SCAN_VERSION:-$(curl -fsSL https://raw.githubusercontent.com/tkdtaylor/dep-scan/main/PINNED_VERSION | tr -d '[:space:]')}" && \
    test -n "$VERSION" && \
    curl -fsSL https://raw.githubusercontent.com/tkdtaylor/dep-scan/main/install.sh \
      | INSTALL_DIR=/usr/local/bin bash -s -- --version="${VERSION}" && \
    dep-scan --version | grep -F -- "${VERSION#v}"

# semgrep + pytest. semgrep's vendored opentelemetry imports pkg_resources, which
# slim Python images no longer bundle AND setuptools >= 81 has removed — so pin
# setuptools < 80 to keep pkg_resources available.
RUN pip install --no-cache-dir "setuptools<80" "semgrep==${SEMGREP_VERSION}" pytest

# Keep pytest's cache out of the (possibly read-only) mounted repo.
ENV PYTEST_ADDOPTS="-p no:cacheprovider"
ENV CODE_SCANNER_REAL_TOOLS=1

WORKDIR /repo
# The repo is mounted at runtime (-v "$PWD:/repo"); nothing is COPYed in, so the
# image stays valid as the working tree changes.
CMD ["python3", "-m", "pytest", "tests/test_gate_cli.py", "-v"]
