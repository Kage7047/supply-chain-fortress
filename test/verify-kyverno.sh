#!/usr/bin/env bash
# Verifies that images were built by Kyverno's own release workflow, at the release this repository
# pins, before the cluster runs them. Kyverno decides which images may run, so it gets the same
# treatment as the images it checks.
#
# Kyverno's release images carry SLSA provenance from slsa-github-generator's reusable workflow
# (cosign finds no plain signature on them). The certificate subject is that generator workflow,
# shared by every project that calls it, so the subject alone proves nothing about who built the
# image (attack a12). The check pins the repository that called the generator, and the tag it ran at
# (attack a11, a downgrade to a genuine older release).
#
#   test/verify-kyverno.sh ghcr.io/kyverno/kyverno@sha256:...
set -euo pipefail

KYVERNO_REPO=${KYVERNO_REPO:-kyverno/kyverno}
KYVERNO_REF=${KYVERNO_REF:-refs/tags/v1.19.2}
GENERATOR=https://github.com/slsa-framework/slsa-github-generator/.github/workflows/generator_container_slsa3.yml@refs/tags/v2.1.0
read -ra extra <<<"${COSIGN_FLAGS:-}"

for image in "$@"; do
  if [[ $image != *@sha256:* ]]; then
    echo "$image: not pinned by digest" >&2
    exit 1
  fi
  if ! out=$(cosign verify-attestation "${extra[@]}" --type slsaprovenance \
    --certificate-oidc-issuer https://token.actions.githubusercontent.com \
    --certificate-identity "$GENERATOR" \
    --certificate-github-workflow-repository "$KYVERNO_REPO" \
    --certificate-github-workflow-ref "$KYVERNO_REF" \
    "$image" 2>&1 >/dev/null); then
    echo "$image: no SLSA provenance from $KYVERNO_REPO at $KYVERNO_REF" >&2
    echo "$out" >&2
    exit 1
  fi
  echo "verified $image: built by $KYVERNO_REPO at $KYVERNO_REF" >&2
done
