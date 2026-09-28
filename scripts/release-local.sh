#!/usr/bin/env bash
# Builds a release snapshot, SBOMs and a signature entirely on this machine, then verifies them.
# Nothing is uploaded: cosign's transparency-log upload is disabled and verification ignores it.
set -euo pipefail
cd "$(dirname "$0")/.."
KEYS=.e2e/release-keys
SYFT=anchore/syft:v1.52.0
mkdir -p "$KEYS" .e2e/release-bin
# goreleaser runs syft from PATH, as the release workflow installs it; here it runs from its image, with
# the working directory mounted at the same path so relative and absolute paths both resolve.
# shellcheck disable=SC2016 # $PWD and $@ are written into the shim, to expand when it runs
printf '#!/usr/bin/env bash\nexec docker run --rm -v "$PWD:$PWD" -w "$PWD" %s "$@"\n' "$SYFT" > .e2e/release-bin/syft
chmod +x .e2e/release-bin/syft
# Signing is done below with a local key, so goreleaser's keyless signing step is skipped.
PATH="$PWD/.e2e/release-bin:$PATH" goreleaser release --snapshot --clean --skip=sign
for a in dist/*.tar.gz dist/*.zip; do
  docker run --rm -v "$PWD/dist:/dist" "$SYFT" "/dist/$(basename "$a")" -o spdx-json="/dist/$(basename "$a").spdx.json" -q
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
