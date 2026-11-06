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
#   narrow           validations check only images.containers, `required` still on
#   narrow-optional  control: validations check only images.containers, `required` off
#   pods-only        control: the policy does not match the pods/ephemeralcontainers subresource
#   fail-open        control: failurePolicy Ignore, for when Kyverno is down
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
metadata: {name: narrow, labels: {fortress.test/images: narrow}}
---
apiVersion: v1
kind: Namespace
metadata: {name: narrow-optional, labels: {fortress.test/images: narrow-optional}}
---
apiVersion: v1
kind: Namespace
metadata: {name: pods-only, labels: {fortress.test/images: pods-only, fortress.test/registries: enforced}}
---
apiVersion: v1
kind: Namespace
metadata: {name: fail-open, labels: {fortress.test/images: fail-open, fortress.test/registries: enforced}}
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
  render policy/image-signatures.yaml --variant narrow --label fortress.test/images --insecure --subject "$SUBJECT" --containers-only
  echo ---
  render policy/image-signatures.yaml --variant narrow-optional --label fortress.test/images --insecure --subject "$SUBJECT" --containers-only --not-required
  echo ---
  render policy/image-signatures.yaml --variant pods-only --label fortress.test/images --insecure --subject "$SUBJECT" --pods-only
  echo ---
  render policy/image-signatures.yaml --variant fail-open --label fortress.test/images --insecure --subject "$SUBJECT" --fail-open
  echo ---
  render policy/allowed-registries.yaml --variant enforced --label fortress.test/registries
} >"$OUT/policies.yaml"
# Retried: Kyverno validates policies through its own webhook, which can take a moment to answer.
for _ in $(seq 30); do kubectl apply -f "$OUT/policies.yaml" && break; sleep 4; done
kubectl apply -f "$OUT/policies.yaml" >/dev/null
kubectl apply -f policy/protect-kyverno.yaml # unmodified: it only concerns Kyverno itself

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
ready narrow "$UNSIGNED"
ready narrow-optional "$UNSIGNED"
ready pods-only "$UNSIGNED"
ready fail-open "$UNSIGNED"

scale_to_zero() { # the request `kubectl scale --replicas=0` sends, without carrying it out
  kubectl -n kyverno scale deployment kyverno-admission-controller --replicas=0 --dry-run=server 2>&1
}
delete_kyverno() {
  kubectl -n kyverno delete deployment kyverno-admission-controller --dry-run=server 2>&1
}
delete_webhooks() { # every webhook configuration Kyverno manages
  kubectl delete validatingwebhookconfigurations,mutatingwebhookconfigurations \
    -l webhook.kyverno.io/managed-by --dry-run=server 2>&1
}
as_kyverno() { # Kyverno itself must still be able to manage them
  kubectl delete validatingwebhookconfigurations -l webhook.kyverno.io/managed-by --dry-run=server \
    --as=system:serviceaccount:kyverno:kyverno-admission-controller 2>&1
}
sa=$(kubectl -n kyverno get deployment kyverno-admission-controller -o jsonpath='{.spec.template.spec.serviceAccountName}')
[[ $sa == kyverno-admission-controller ]] ||
  { echo "Kyverno runs as service account '$sa'; policy/protect-kyverno.yaml exempts kyverno-admission-controller" >&2; exit 1; }
for _ in $(seq 60); do scale_to_zero >/dev/null || break; sleep 2; done
for _ in $(seq 60); do delete_webhooks >/dev/null || break; sleep 2; done
ready enforced "$BUSYBOX"

# a08 needs a pod that already exists: `kubectl debug` adds its container to a running pod
# through the pods/ephemeralcontainers subresource, after the pod itself was admitted. The pods
# are admitted with the genuine image and never pulled (the node cannot reach the test registry
# over plain HTTP), which does not matter: adding an ephemeral container is still an admission
# request.
for ns in enforced pods-only; do pod target "$ns" "$GOOD" | kubectl apply -f - >/dev/null; done

debug() { # name namespace image: what `kubectl debug target --image=<image>` sends
  kubectl -n "$2" patch pod target --subresource=ephemeralcontainers --type=strategic \
    --dry-run=server -o yaml -p "{\"spec\":{\"ephemeralContainers\":[{\"name\":\"$1\",\"image\":\"$3\"}]}}" 2>&1
}

deploy() { # name namespace image: a Deployment, checked when it is created (autogen)
  kubectl apply --dry-run=server -o yaml -f - 2>&1 <<YAML
{apiVersion: apps/v1, kind: Deployment, metadata: {name: $1, namespace: $2}, spec: {selector: {matchLabels: {app: $1}},
 template: {metadata: {labels: {app: $1}}, spec: {containers: [{name: app, image: "$3"}]}}}}
YAML
}

rows=()
failed=0
check() { # id want namespace description image [init-image]; ATTEMPT=debug for a08
  local id=$1 want=$2 ns=$3 what=$4 out got result
  shift 4
  if out=$(${ATTEMPT:-admit} "$id" "$ns" "$@"); then got=admitted; else got=denied; fi
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
check a06n "denied:no policy performed a signature or attestation check" narrow \
  "unsigned init container, validations check only containers: \`required\` refuses it" "$GOOD" "$UNSIGNED"
check c06 admitted narrow-optional "control: unsigned init container, only containers checked, required off" "$GOOD" "$UNSIGNED"

check a07 "denied:$not_signed" prod-identity "signed in CI, but not by release.yml on main" "$GOOD"

ATTEMPT=debug check a08 "denied:$not_signed" enforced "kubectl debug: unsigned ephemeral container on a running pod" "$UNSIGNED"
ATTEMPT=debug check c08 admitted pods-only "control: kubectl debug, policy does not match the subresource" "$UNSIGNED"

ATTEMPT=deploy check ok4 "admitted@$good_digest" enforced "genuine image in a Deployment, by tag: rewritten to the digest" "$REPO:good"
ATTEMPT=deploy check a13 "denied:$not_signed" enforced "unsigned image in a Deployment, refused before any pod exists" "$UNSIGNED"
ATTEMPT=deploy check c13 admitted no-policy "control: unsigned Deployment, no policy" "$UNSIGNED"

# The guard on Kyverno itself (policy/protect-kyverno.yaml).
ATTEMPT=scale_to_zero check a14 "denied:cannot be scaled to zero" kyverno "scale Kyverno to zero (an incident, a script, an autoscaler)"
ATTEMPT=delete_kyverno check a14d "denied:cannot be deleted" kyverno "delete Kyverno's Deployment"
ATTEMPT=delete_webhooks check a15 "denied:only Kyverno may change or delete" cluster "delete Kyverno's webhook configurations"
ATTEMPT=as_kyverno check ok6 admitted cluster "Kyverno itself may still delete them"

# a09: Kyverno is deployed but cannot answer: hung, overloaded, or cut off. Simulated by freezing
# its process (SIGSTOP from the node). Changing its Service is not enough: the API server keeps its
# open connection to the old pod. The three requests run at once, so the whole test fits inside
# the webhook timeout, before the liveness probe restarts Kyverno.
signal_kyverno() { # STOP|CONT
  docker exec fortress-control-plane sh -c 'n=0; for p in /proc/[0-9]*; do
    [ "$(cat "$p/comm" 2>/dev/null)" = kyverno ] && kill -'"$1"' "${p#/proc/}" && n=$((n+1)); done; [ "$n" -gt 0 ]'
}
hung() { cat "$OUT/hung-$1.out"; return "$(cat "$OUT/hung-$1.rc")"; }
signal_kyverno STOP
for job in "a09 enforced $UNSIGNED" "p09 enforced $GOOD" "c09 fail-open $UNSIGNED"; do
  read -r id ns image <<<"$job"
  (if admit "$id" "$ns" "$image" >"$OUT/hung-$id.out"; then echo 0; else echo 1; fi >"$OUT/hung-$id.rc") &
done
wait
signal_kyverno CONT
down="failed calling webhook"
ATTEMPT=hung check a09 "denied:$down" enforced "Kyverno hung: unsigned image"
ATTEMPT=hung check p09 "denied:$down" enforced "Kyverno hung: the genuine image is refused too (the price of failing closed)"
ATTEMPT=hung check c09 admitted fail-open "control: Kyverno hung, failurePolicy Ignore lets the unsigned image in"
ready enforced "$UNSIGNED"

# c14, last because it takes Kyverno away for good: without the guard, scaling to zero is allowed.
# Kyverno deletes its webhooks on the way down, and failurePolicy: Fail never gets a say.
kubectl delete validatingadmissionpolicybinding fortress-kyverno-stays-up fortress-kyverno-webhooks-stay >/dev/null
for _ in $(seq 60); do scale_to_zero >/dev/null && break; sleep 2; done
ATTEMPT=delete_webhooks check c15 admitted cluster "control: no guard, a cluster admin deletes Kyverno's webhook configurations"
kubectl -n kyverno scale deployment kyverno-admission-controller --replicas=0 >/dev/null
kubectl -n kyverno wait --for=delete pod -l app.kubernetes.io/component=admission-controller --timeout=120s >/dev/null
webhooks=$(kubectl get validatingwebhookconfigurations -l webhook.kyverno.io/managed-by=kyverno -o name | wc -l)
check c14 admitted enforced "control: no guard, Kyverno scaled to zero ($webhooks webhooks left): unsigned image admitted" "$UNSIGNED"
{
  echo "### Cluster attacks"
  echo
  echo "| id | namespace | what | want | got | result |"
  echo "|---|---|---|---|---|---|"
  printf '%s\n' "${rows[@]}"
} >"$OUT/attacks.md"
[[ -n ${GITHUB_STEP_SUMMARY:-} ]] && cat "$OUT/attacks.md" >>"$GITHUB_STEP_SUMMARY"
exit $failed
