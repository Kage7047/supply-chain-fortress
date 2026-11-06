#!/usr/bin/env bash
# Installs the cluster test tools into ./bin, each pinned: Go tools through the Go checksum
# database, downloaded binaries by a sha256 written here. cosign comes from sigstore's installer
# action, which verifies its own download.
set -euo pipefail

KUBECTL_VERSION=v1.36.6
KUBECTL_SHA256=29818b6729dc9262b692307470d0558d027725e738be5dd47c760261868a2634
HELM_VERSION=v3.22.1
HELM_SHA256=896cf63684a42a723d61c980369d6e588330927deb13676ca0d85006dd6da0ea

bin="$PWD/bin"
mkdir -p "$bin"
export GOBIN="$bin"

go install sigs.k8s.io/kind@v0.33.0
go install github.com/google/ko@v0.19.1
go install github.com/google/go-containerregistry/cmd/crane@v0.22.1

curl -fsSL "https://dl.k8s.io/release/$KUBECTL_VERSION/bin/linux/amd64/kubectl" -o "$bin/kubectl"
echo "$KUBECTL_SHA256  $bin/kubectl" | sha256sum -c -
chmod +x "$bin/kubectl"

tmp=$(mktemp -d)
curl -fsSL "https://get.helm.sh/helm-$HELM_VERSION-linux-amd64.tar.gz" -o "$tmp/helm.tgz"
echo "$HELM_SHA256  $tmp/helm.tgz" | sha256sum -c -
tar -xzf "$tmp/helm.tgz" -C "$tmp"
mv "$tmp/linux-amd64/helm" "$bin/helm"

echo "$bin" >>"${GITHUB_PATH:-/dev/null}"
