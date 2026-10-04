#!/usr/bin/env bash
# Checks a published release against dist/ (goreleaser's output in the release job, or the release's
# assets downloaded into dist/): every archive matches checksums.txt, checksums.txt and the image carry
# keyless signatures made by the release workflow at that release's tag, and the image runs the release.
# usage: verify-release.sh VERSION   (e.g. 0.1.0; needs cosign and docker)
set -euo pipefail
cd "$(dirname "$0")/.."
version=${1:?usage: verify-release.sh VERSION}
repo=${GITHUB_REPOSITORY:-Bisman-Singh/sievelog}
identity="https://github.com/${repo}/.github/workflows/release.yml@refs/tags/v${version}"
issuer=https://token.actions.githubusercontent.com
image="ghcr.io/$(printf '%s' "${repo}" | tr '[:upper:]' '[:lower:]'):${version}"
sha256() { if command -v sha256sum >/dev/null; then sha256sum "$@"; else shasum -a 256 "$@"; fi; }

(cd dist && sha256 -c checksums.txt --ignore-missing >/dev/null)
echo "archives and SBOMs match checksums.txt"
cosign verify-blob --certificate-identity "${identity}" --certificate-oidc-issuer "${issuer}" \
  --certificate dist/checksums.txt.pem --signature dist/checksums.txt.sig dist/checksums.txt
cosign verify --certificate-identity "${identity}" --certificate-oidc-issuer "${issuer}" "${image}" >/dev/null
echo "the image ${image} is signed by ${identity}"
got=$(docker run --rm "${image}" version)
case "${got}" in
  "sievelog ${version} "*) echo "the image runs ${got}" ;;
  *) echo "the image runs ${got}, not ${version}" >&2; exit 1 ;;
esac
