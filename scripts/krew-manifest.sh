#!/usr/bin/env bash
# Print the krew manifest for a release, using the checksums from goreleaser.
#   scripts/krew-manifest.sh v0.1.0 > plugins/java4shell.yaml
set -euo pipefail

VERSION="${1:?usage: $0 vX.Y.Z [checksums.txt]}"
CHECKSUMS="${2:-dist/checksums.txt}"
REPO="https://github.com/simonliska/java4shell-k8s-scanner"

cat <<EOF
apiVersion: krew.googlecontainertools.github.com/v1alpha2
kind: Plugin
metadata:
  name: java4shell
spec:
  version: $VERSION
  homepage: $REPO
  shortDescription: Find pods exposed to java4shell (CVE-2026-114938)
  description: |
    Reports which pods are actually exposed to java4shell (CVE-2026-114938):
    an affected JDK on a node whose CPU has avx512vbmi, with no mitigation
    flag set. Also flags pods that could be rescheduled onto such nodes.
    Needs Node Feature Discovery in the cluster.
  platforms:
EOF

for os in linux darwin windows; do
  for arch in amd64 arm64; do
    archive="kubectl-java4shell_${os}_${arch}.tar.gz"
    sha="$(awk -v f="$archive" '$2 == f { print $1 }' "$CHECKSUMS")"
    [[ -n "$sha" ]] || { echo "no checksum for $archive in $CHECKSUMS" >&2; exit 1; }
    bin="kubectl-java4shell"
    [[ "$os" == "windows" ]] && bin="$bin.exe"
    cat <<EOF
    - selector:
        matchLabels: {os: $os, arch: $arch}
      uri: $REPO/releases/download/$VERSION/$archive
      sha256: $sha
      bin: $bin
EOF
  done
done
