#!/usr/bin/env bash
# Local gate before every commit: formatting, vet (including e2e build tags), unit tests, and the
# third-party licences the binaries ship with.
set -euo pipefail
cd "$(dirname "$0")/.."
unformatted=$(gofmt -l .)
if [ -n "${unformatted}" ]; then
  echo "gofmt needed:"; echo "${unformatted}"; exit 1
fi
go vet ./...
go vet -tags e2e ./e2e/...
go vet -tags docker ./...
go test ./... -count=1
./scripts/third-party.sh --check
