#!/usr/bin/env bash
# Applies the production policies exactly as they are in policy/ and checks that the image the
# release workflow just signed is admitted, rewritten to its digest, and that the same pod with an
# image from anywhere else is not. The attack tests run on rendered copies; this is the check that
# the unmodified files let the real thing through.
#
#   test/admit.sh ghcr.io/kage7047/supply-chain-fortress/app@sha256:...
set -euo pipefail

image=${1:?usage: admit.sh <released image by digest>}
digest=${image#*@}
tag_ref="${image%@*}:${GITHUB_SHA:?}"
BUSYBOX=docker.io/library/busybox@sha256:a7dbc319b1438115a207e11930dc4bb3e643dcb3ec0bdd694bb36cd8fad289ec

kubectl apply -f policy/
kubectl create namespace release-check

admit() { # name image
  echo "{apiVersion: v1, kind: Pod, metadata: {name: $1, namespace: release-check}, spec: {containers: [{name: app, image: \"$2\"}]}}" |
    kubectl apply --dry-run=server -o yaml -f - 2>&1
}

# Wait until the policies are live: the foreign image starts being refused.
for _ in $(seq 90); do
  admit probe "$BUSYBOX" >/dev/null || break
  sleep 2
done
if admit probe "$BUSYBOX" >/dev/null; then
  echo "production policies never took effect" >&2
  exit 1
fi

# By tag, so the check also covers the rewrite to the verified digest.
if ! out=$(admit release "$tag_ref"); then
  echo "the released image was refused by the production policies:" >&2
  echo "$out" >&2
  exit 1
fi
if [[ $out != *"$digest"* ]]; then
  echo "admitted, but not pinned to the verified digest $digest:" >&2
  echo "$out" >&2
  exit 1
fi
echo "ok: $tag_ref admitted as $digest"
