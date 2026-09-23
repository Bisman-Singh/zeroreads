#!/usr/bin/env bash
# Differential tests against real runtime engines in docker (Vector VRL, and more as added).
set -euo pipefail
cd "$(dirname "$0")/.."
go vet -tags docker ./...
go test -tags docker ./internal/dialect/... -count=1 -timeout 30m
