#!/usr/bin/env bash
# Runs the cluster attacks against the real policy files and checks three things for each:
#
#   - the genuine image is admitted (a policy that refuses everything would pass every attack),
#   - each attack is refused, with the message of the defence that is meant to stop it,
#   - each attack is admitted where that defence is missing (the control: the attack is real,
#     and it is this defence, not some accident of the test, that stops it).
#
# Every pod is sent with `kubectl apply --dry-run=server`: it goes through admission exactly like a
# real one, but nothing is scheduled or pulled.
#
#   SUBJECT=https://github.com/$GITHUB_WORKFLOW_REF test/attacks.sh 172.18.0.3:5000
set -euo pipefail

registry=${1:?usage: attacks.sh <registry host:port>}
: "${SUBJECT:?SUBJECT must be the signing identity of this run (https://github.com/<workflow ref>)}"
OUT=${OUT:-test/out}
# shellcheck source=/dev/null
source "$OUT/images.env"
BUSYBOX=docker.io/library/busybox@sha256:a7dbc319b1438115a207e11930dc4bb3e643dcb3ec0bdd694bb36cd8fad289ec
prefix="$registry/fortress/"

# Namespaces, and which policy variants bind to them.
#   enforced         the production policies, signer = this run
#   prod-identity    the production policies, signer = release.yml on main (unchanged)
#   signatures-only  control: the signature policy without the registry allowlist
#   containers-only  control: a signature policy that checks only images.containers
#   no-policy        control: nothing
kubectl apply -f - >/dev/null <<EOF
apiVersion: v1
kind: Namespace
metadata: {name: enforced, labels: {fortress.test/images: enforced, fortress.test/registries: enforced}}
---
apiVersion: v1
kind: Namespace
metadata: {name: prod-identity, labels: {fortress.test/images: prod-identity, fortress.test/registries: enforced}}
---
apiVersion: v1
kind: Namespace
metadata: {name: signatures-only, labels: {fortress.test/images: enforced}}
---
apiVersion: v1
kind: Namespace
metadata: {name: containers-only, labels: {fortress.test/images: containers-only}}
---
apiVersion: v1
kind: Namespace
metadata: {name: no-policy}
EOF

render() { python3 test/render.py "$@" --registry "$prefix"; }
{
  render policy/image-signatures.yaml --variant enforced --label fortress.test/images --insecure --subject "$SUBJECT"
  echo ---
  render policy/image-signatures.yaml --variant prod-identity --label fortress.test/images --insecure
  echo ---
  render policy/image-signatures.yaml --variant containers-only --label fortress.test/images --insecure --subject "$SUBJECT" --containers-only
  echo ---
  render policy/allowed-registries.yaml --variant enforced --label fortress.test/registries
} >"$OUT/policies.yaml"
kubectl apply -f "$OUT/policies.yaml"

pod() { # name namespace image [init-image]
  echo "{apiVersion: v1, kind: Pod, metadata: {name: $1, namespace: $2}, spec: {"
  [[ -n ${4:-} ]] && echo "initContainers: [{name: init, image: \"$4\"}],"
  echo "containers: [{name: app, image: \"$3\"}]}}"
}

admit() { # name namespace image [init-image]; prints the admitted pod, or the refusal, and fails on refusal
  pod "$@" | kubectl apply --dry-run=server -o yaml -f - 2>&1
}

# Policies take effect a few seconds after they are created. Wait until each variant refuses
# something it should, so the first real check does not race the webhook configuration.
ready() { # namespace image [init]
  for _ in $(seq 90); do
    admit probe "$@" >/dev/null || return 0
    sleep 2
  done
  echo "policies in namespace $1 never started refusing; Kyverno logs:" >&2
  kubectl -n kyverno logs -l app.kubernetes.io/component=admission-controller --tail=100 >&2
  exit 1
}
ready enforced "$UNSIGNED"
ready prod-identity "$GOOD"
ready containers-only "$UNSIGNED"
ready enforced "$BUSYBOX"

rows=()
failed=0
check() { # id want namespace description image [init-image]
  local id=$1 want=$2 ns=$3 what=$4 out got result
  shift 4
  if out=$(admit "$id" "$ns" "$@"); then got=admitted; else got=denied; fi
  result=ok
  case $want in
    admitted) [[ $got == admitted ]] || result=FAIL ;;
    admitted@*) [[ $got == admitted && $out == *"${want#admitted}"* ]] || result=FAIL ;;
    denied:*) [[ $got == denied && $out == *"${want#denied:}"* ]] || result=FAIL ;;
  esac
  if [[ $result == FAIL ]]; then
    failed=1
    printf '\n%s: wanted %s, got %s\n%s\n' "$id" "$want" "$got" "$out" >&2
  fi
  rows+=("| $id | $ns | $what | ${want%%:*} | $got | $result |")
  printf '%-4s %-5s %-16s %-9s %s\n' "$result" "$id" "$ns" "$got" "$what"
}

good_digest=${GOOD#*@}
not_signed="image is not signed by the release workflow on main"

check ok1 admitted enforced "genuine image, by digest" "$GOOD"
check ok2 "admitted@$good_digest" enforced "genuine image, by tag: rewritten to the verified digest" "$REPO:good"
check ok3 "admitted@$good_digest" enforced "tag v1 while it still points at the genuine image" "$REPO:v1"

check a01 "denied:$not_signed" enforced "unsigned image" "$UNSIGNED"
check c01 admitted no-policy "control: unsigned image, no policy" "$UNSIGNED"

check a02 "denied:$not_signed" enforced "signed and attested with the attacker's own key" "$ATTACKER"
check c02 admitted no-policy "control: attacker-signed image, no policy" "$ATTACKER"

check a03 "denied:image has no SBOM attested" enforced "signed by the right workflow, no SBOM attestation" "$NOSBOM"
check c03 admitted no-policy "control: image without SBOM, no policy" "$NOSBOM"

# 04: after verification, the attacker moves the tag to their own image.
crane tag --insecure "$UNSIGNED" v1
check a04 "denied:$not_signed" enforced "tag v1 re-pointed at an unsigned image" "$REPO:v1"
check c04 admitted no-policy "control: re-pointed tag, no policy" "$REPO:v1"

check a05 "denied:image from outside the allowed registry" enforced "image from another registry" "$BUSYBOX"
check c05 admitted signatures-only "control: another registry, signature policy alone" "$BUSYBOX"

check a06 "denied:$not_signed" enforced "genuine app, unsigned init container" "$GOOD" "$UNSIGNED"
check c06 admitted containers-only "control: unsigned init container, policy checks only containers" "$GOOD" "$UNSIGNED"

check a07 "denied:$not_signed" prod-identity "signed in CI, but not by release.yml on main" "$GOOD"

{
  echo "### Cluster attacks"
  echo
  echo "| id | namespace | what | want | got | result |"
  echo "|---|---|---|---|---|---|"
  printf '%s\n' "${rows[@]}"
} >"$OUT/attacks.md"
[[ -n ${GITHUB_STEP_SUMMARY:-} ]] && cat "$OUT/attacks.md" >>"$GITHUB_STEP_SUMMARY"
exit $failed
