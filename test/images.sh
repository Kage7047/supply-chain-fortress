#!/usr/bin/env bash
# Builds the app into the test registry and makes one image per attack, each signed (or not) the
# way that attack needs. Writes test/out/images.env for test/attacks.sh.
#
# The genuine image is signed keyless by whatever runs this script, through GitHub's OIDC token,
# so it only works inside GitHub Actions with `id-token: write`.
#
#   test/images.sh 172.18.0.3:5000
set -euo pipefail

registry=${1:?usage: images.sh <registry host:port>}
repo="$registry/fortress/app"
OUT=${OUT:-test/out}
mkdir -p "$OUT"
export COSIGN_YES=true
cosign_flags=(--allow-insecure-registry --allow-http-registry)

digest_ref() { echo "$repo@$(crane digest --insecure "$1")"; }

# A copy of an image with one label changed: same code, new digest, and none of the original's
# signatures or attestations, which are bound to the old digest.
variant() {
  crane mutate --insecure "$good" --label "fortress.attack=$1" -t "$repo:$1" >/dev/null
  digest_ref "$repo:$1"
}

# The genuine image: built from this commit, signed by this workflow, SBOM attested.
KO_DOCKER_REPO=$repo ko build ./app --bare --insecure-registry --tags good \
  --sbom-dir "$OUT/sbom" --image-refs "$OUT/good.ref" >&2
good="$repo@$(sed 's/.*@//' "$OUT/good.ref")"
sbom=$(find "$OUT/sbom" -name '*.json' | head -1)
[[ -n $sbom ]] || { echo "ko wrote no SBOM" >&2; exit 1; }
cosign sign "${cosign_flags[@]}" "$good" >&2
cosign attest "${cosign_flags[@]}" --type spdxjson --predicate "$sbom" "$good" >&2

# 01: never signed.
unsigned=$(variant unsigned)

# 02: signed and attested, but with a key the attacker generated, not by the release workflow.
COSIGN_PASSWORD= cosign generate-key-pair --output-key-prefix "$OUT/attacker" >&2
attacker=$(variant attacker-key)
COSIGN_PASSWORD= cosign sign "${cosign_flags[@]}" --key "$OUT/attacker.key" "$attacker" >&2
COSIGN_PASSWORD= cosign attest "${cosign_flags[@]}" --key "$OUT/attacker.key" \
  --type spdxjson --predicate "$sbom" "$attacker" >&2

# 03: signed by the right workflow, but nobody attested what is inside it.
nosbom=$(variant no-sbom)
cosign sign "${cosign_flags[@]}" "$nosbom" >&2

# 04: the tag "v1" starts on the genuine image. attacks.sh re-points it later.
crane tag --insecure "$good" v1

cat >"$OUT/images.env" <<EOF
REPO=$repo
GOOD=$good
UNSIGNED=$unsigned
ATTACKER=$attacker
NOSBOM=$nosbom
EOF
cat "$OUT/images.env" >&2
