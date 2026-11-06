#!/usr/bin/env bash
# Attacks on the policy engine's own images. The defence is test/verify-kyverno.sh, which
# test/cluster-up.sh runs before installing Kyverno. Same three checks as test/attacks.sh: the
# genuine images pass, each attack is refused for the right reason, and a weaker check that real
# guides suggest accepts the same attack (the control).
#
# a10 re-signs a modified copy keyless with this run's identity, so it needs GitHub's OIDC token
# and the test registry.
#
#   test/kyverno-trust.sh 172.18.0.3:5000
set -euo pipefail

registry=${1:?usage: kyverno-trust.sh <registry host:port>}
OUT=${OUT:-test/out}
mkdir -p "$OUT"
# shellcheck source=test/kyverno.env
source test/kyverno.env
export KYVERNO_REF COSIGN_YES=true
GITHUB_OIDC=https://token.actions.githubusercontent.com
GENERATOR=https://github.com/slsa-framework/slsa-github-generator/.github/workflows/generator_container_slsa3.yml@refs/tags/v2.1.0
local_flags=(--allow-insecure-registry --allow-http-registry)

# a11: a genuine Kyverno image from an older release: real provenance, real repository, wrong tag.
OLD_RELEASE=ghcr.io/kyverno/kyverno@sha256:0a540e2ddf74d0d2d3d45f9ef248d7dbc96576accdbcc6a2dd7eaff9fea56504 # v1.18.2
# a12: another project's image with genuine SLSA provenance from the same generator workflow.
OTHER_PROJECT=ghcr.io/projectbeskar/virtrigaud/manager@sha256:e66a7d03357fc18b3eec38a82c5281c3257c5e26fddd1b856c07379ce32d93bb # v0.4.2

# a10: Kyverno's image with one label changed (in a real attack, a backdoor), and Kyverno's own
# provenance document attached to it, signed keyless by someone else's GitHub workflow.
copy="$registry/kyverno/kyverno"
crane copy --platform linux/amd64 "$KYVERNO_IMAGE" "$copy:upstream" --insecure >/dev/null
crane mutate --insecure "$copy:upstream" --label fortress.attack=backdoor -t "$copy:backdoor" >/dev/null
backdoor="$copy@$(crane digest --insecure "$copy:backdoor")"
cosign verify-attestation --type slsaprovenance --certificate-oidc-issuer "$GITHUB_OIDC" \
  --certificate-identity "$GENERATOR" "$KYVERNO_IMAGE" 2>/dev/null | head -1 |
  python3 -c 'import sys,json,base64; print(json.dumps(json.loads(base64.b64decode(json.load(sys.stdin)["payload"]))["predicate"]))' \
    >"$OUT/kyverno-provenance.json"
cosign attest "${local_flags[@]}" --type slsaprovenance --predicate "$OUT/kyverno-provenance.json" "$backdoor" >&2

verify() { test/verify-kyverno.sh "$@" 2>&1; }
local_verify() { COSIGN_FLAGS="${local_flags[*]}" test/verify-kyverno.sh "$@" 2>&1; }
# The controls: checks as they are often written.
any_github_workflow() { # "signed in GitHub Actions"
  cosign verify-attestation "${local_flags[@]}" --type slsaprovenance --certificate-oidc-issuer "$GITHUB_OIDC" \
    --certificate-identity-regexp '^https://github\.com/' "$1" 2>&1 >/dev/null
}
generator_only() { # the certificate subject is the SLSA generator
  cosign verify-attestation --type slsaprovenance --certificate-oidc-issuer "$GITHUB_OIDC" \
    --certificate-identity "$GENERATOR" "$1" 2>&1 >/dev/null
}
any_release() { # the right repository, any tag
  cosign verify-attestation --type slsaprovenance --certificate-oidc-issuer "$GITHUB_OIDC" \
    --certificate-identity "$GENERATOR" --certificate-github-workflow-repository kyverno/kyverno "$1" 2>&1 >/dev/null
}

rows=()
failed=0
check() { # id want check description args...
  local id=$1 want=$2 fn=$3 what=$4 out got result=ok
  shift 4
  if out=$("$fn" "$@"); then got=accepted; else got=refused; fi
  case $want in
    accepted) [[ $got == accepted ]] || result=FAIL ;;
    refused:*) [[ $got == refused && $out == *"${want#refused:}"* ]] || result=FAIL ;;
  esac
  if [[ $result == FAIL ]]; then
    failed=1
    printf '\n%s: wanted %s, got %s\n%s\n' "$id" "$want" "$got" "$out" >&2
  fi
  rows+=("| $id | $fn | $what | ${want%%:*} | $got | $result |")
  printf '%-4s %-5s %-19s %-8s %s\n' "$result" "$id" "$fn" "$got" "$what"
}

check ok4 accepted verify "genuine Kyverno admission controller, $KYVERNO_REF" "$KYVERNO_IMAGE"
check ok5 accepted verify "genuine Kyverno init container, $KYVERNO_REF" "$KYVERNO_PRE_IMAGE"

check a10 "refused:no matching CertificateIdentity" local_verify \
  "modified Kyverno with Kyverno's provenance text, signed by another workflow" "$backdoor"
check c10 accepted any_github_workflow "control: check only that a GitHub workflow signed it" "$backdoor"

check a11 "refused:expected GitHub Workflow Ref not found" verify "genuine Kyverno v1.18.2: a downgrade" "$OLD_RELEASE"
check c11 accepted any_release "control: right repository, any tag" "$OLD_RELEASE"

check a12 "refused:expected GitHub Workflow Repository not found" verify \
  "another project's image, provenance from the same SLSA generator" "$OTHER_PROJECT"
check c12 accepted generator_only "control: check only the certificate subject (the generator)" "$OTHER_PROJECT"

{
  echo "### Kyverno's own images"
  echo
  echo "| id | check | what | want | got | result |"
  echo "|---|---|---|---|---|---|"
  printf '%s\n' "${rows[@]}"
} >"$OUT/kyverno-trust.md"
[[ -n ${GITHUB_STEP_SUMMARY:-} ]] && cat "$OUT/kyverno-trust.md" >>"$GITHUB_STEP_SUMMARY"
exit $failed
