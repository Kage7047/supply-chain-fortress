#!/usr/bin/env bash
# Starts the test cluster: kind, a local OCI registry on kind's network, and Kyverno.
# Everything is pinned by digest or checksum, including the policy engine that guards the rest.
# Prints the registry address for test/images.sh and test/attacks.sh.
set -euo pipefail

KIND_NODE=kindest/node:v1.36.4@sha256:099e049362a1526b2db71494e1947aae99bd16290d7c895f2b7ea312e3cbfaed
REGISTRY_IMAGE=docker.io/library/registry:3@sha256:38907510915c3f1604c7e83d6ab602ab3020d092f73bdaed8696773693ff768c
KYVERNO_CHART=https://kyverno.github.io/kyverno/kyverno-3.9.2.tgz
KYVERNO_CHART_SHA256=f6fe7184544d5e2ee33a77808c09e67aa603ce6560cc197038fde31d727c861e
OUT=${OUT:-test/out}
mkdir -p "$OUT"
# shellcheck source=test/kyverno.env
source test/kyverno.env
export KYVERNO_REF

# The policy engine decides what runs, so its own images are checked before anything else happens.
test/verify-kyverno.sh "$KYVERNO_IMAGE" "$KYVERNO_PRE_IMAGE"

kind create cluster --name fortress --image "$KIND_NODE" --wait 120s >&2

# The registry sits on kind's docker network and is addressed by IP, so the runner (which builds
# and signs) and Kyverno's pods (which verify) name every image identically.
docker run -d --restart=always --name fortress-registry --network kind "$REGISTRY_IMAGE" >&2
ip=$(docker inspect -f '{{(index .NetworkSettings.Networks "kind").IPAddress}}' fortress-registry)
registry="$ip:5000"
for _ in $(seq 30); do curl -fs "http://$registry/v2/" >/dev/null && break; sleep 1; done
curl -fs "http://$registry/v2/" >/dev/null || { echo "registry at $registry did not come up" >&2; exit 1; }

curl -fsSL "$KYVERNO_CHART" -o "$OUT/kyverno.tgz"
echo "$KYVERNO_CHART_SHA256  $OUT/kyverno.tgz" | sha256sum -c - >&2
# The chart names its images by tag on reg.kyverno.io. Install the verified digests instead
# ("repo:tag@digest": the runtime pulls the digest). The pre-delete hook's image is tagged
# `latest` and never verified, so that hook is off.
tag=${KYVERNO_REF#refs/tags/}
helm install kyverno "$OUT/kyverno.tgz" -n kyverno --create-namespace --wait --timeout 5m \
  --set backgroundController.enabled=false \
  --set cleanupController.enabled=false \
  --set reportsController.enabled=false \
  --set webhooksCleanup.enabled=false \
  --set admissionController.container.image.registry=ghcr.io \
  --set admissionController.container.image.repository=kyverno/kyverno \
  --set-string admissionController.container.image.tag="$tag@${KYVERNO_IMAGE#*@}" \
  --set admissionController.initContainer.image.registry=ghcr.io \
  --set admissionController.initContainer.image.repository=kyverno/kyvernopre \
  --set-string admissionController.initContainer.image.tag="$tag@${KYVERNO_PRE_IMAGE#*@}" >&2

# Every container Kyverno runs must be one of the two verified digests.
running=$(kubectl -n kyverno get pods -o jsonpath='{range .items[*]}{range .status.initContainerStatuses[*]}{.imageID}{"\n"}{end}{range .status.containerStatuses[*]}{.imageID}{"\n"}{end}{end}' | sort -u)
for id in $running; do
  case ${id##*@} in
    "${KYVERNO_IMAGE#*@}" | "${KYVERNO_PRE_IMAGE#*@}") ;;
    *) echo "Kyverno is running an image nobody verified: $id" >&2; exit 1 ;;
  esac
done
echo "Kyverno runs only verified images:" $running >&2

echo "$registry"
