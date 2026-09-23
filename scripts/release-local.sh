#!/usr/bin/env bash
# Builds a release snapshot, SBOMs and a signature entirely on this machine, then verifies them.
# Nothing is uploaded: cosign's transparency-log upload is disabled and verification ignores it.
set -euo pipefail
cd "$(dirname "$0")/.."
KEYS=.e2e/release-keys
mkdir -p "$KEYS"
goreleaser release --snapshot --clean
for a in dist/*.tar.gz dist/*.zip; do
  docker run --rm -v "$PWD/dist:/dist" anchore/syft:latest "/dist/$(basename "$a")" -o spdx-json="/dist/$(basename "$a").spdx.json" -q
done
export COSIGN_PASSWORD="${COSIGN_PASSWORD:-local-snapshot-only}"
if [ ! -f "$KEYS/cosign.key" ]; then
  docker run --rm -e COSIGN_PASSWORD -v "$PWD/$KEYS:/k" -w /k gcr.io/projectsigstore/cosign:v2.5.3 generate-key-pair
fi
docker run --rm -e COSIGN_PASSWORD -v "$PWD:/w" -w /w gcr.io/projectsigstore/cosign:v2.5.3 \
  sign-blob --yes --tlog-upload=false --key "$KEYS/cosign.key" --output-signature dist/checksums.txt.sig dist/checksums.txt
docker run --rm -v "$PWD:/w" -w /w gcr.io/projectsigstore/cosign:v2.5.3 \
  verify-blob --insecure-ignore-tlog --key "$KEYS/cosign.pub" --signature dist/checksums.txt.sig dist/checksums.txt
(cd dist && shasum -a 256 -c checksums.txt --ignore-missing)
