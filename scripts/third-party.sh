#!/usr/bin/env bash
# Writes THIRD_PARTY_LICENSES: the licence and notice files of Go and of every module linked into the
# release binaries, on every platform goreleaser builds. Binary distributions must carry them, and the
# archives and images do. With --check it only fails when the committed file is not what it would write.
set -euo pipefail
cd "$(dirname "$0")/.."
OUT=THIRD_PARTY_LICENSES
GO_VERSION=$(sed -n 's/^go //p' go.mod)

modules() {
  for os in linux darwin windows; do
    for arch in amd64 arm64; do
      GOOS=${os} GOARCH=${arch} CGO_ENABLED=0 go list -deps \
        -f '{{with .Module}}{{if not .Main}}{{.Path}}@{{.Version}}{{end}}{{end}}' ./cmd/sievelog
    done
  done | sort -u
}

section() { # title, file
  printf '%s\n%s\n%s\n\n' "================================================================================" "$1" "================================================================================"
  cat "$2"
  printf '\n'
}

generate() {
  printf 'sievelog includes the Go standard library and runtime, and the modules below. Each one is listed\n'
  printf 'with its version, followed by its licence and notice files as published.\n\n'
  local goroot golicense
  goroot=$(go env GOROOT)
  golicense=${goroot}/LICENSE
  [ -f "${golicense}" ] || golicense=$(dirname "${goroot}")/LICENSE # some packagings keep it beside GOROOT
  section "Go ${GO_VERSION}: LICENSE" "${golicense}"
  local mod dir found f
  for mod in $(modules); do
    dir=$(go mod download -json "${mod}" | sed -n 's/^[[:space:]]*"Dir": "\(.*\)",$/\1/p')
    found=0
    while IFS= read -r f; do
      section "${mod%@*} ${mod#*@}: $(basename "${f}")" "${f}"
      found=1
    done < <(find "${dir}" -maxdepth 1 -type f \( -iname 'LICENSE*' -o -iname 'LICENCE*' -o -iname 'COPYING*' -o -iname 'NOTICE*' \) | LC_ALL=C sort)
    if [ "${found}" = 0 ]; then
      echo "no licence file in ${mod} (${dir})" >&2
      exit 1
    fi
  done
}

if [ "${1:-}" = "--check" ]; then
  tmp=$(mktemp)
  trap 'rm -f "${tmp}"' EXIT
  generate > "${tmp}"
  if ! cmp -s "${tmp}" "${OUT}"; then
    echo "${OUT} is out of date: run scripts/third-party.sh" >&2
    exit 1
  fi
  if [ "$(sed -n 's/^- \([^ ]*\) (.*/\1/p' NOTICE | sort)" != "$(modules)" ]; then
    echo "NOTICE does not list exactly the linked modules:" >&2
    diff <(sed -n 's/^- \([^ ]*\) (.*/\1/p' NOTICE | sort) <(modules) >&2 || true
    exit 1
  fi
  exit 0
fi
generate > "${OUT}"
