#!/usr/bin/env bash
# Checks the workflow attacks. Each file in attacks/workflows/ names, on its "# expect:" line, the
# zizmor audit that must flag it. Its fixed version in attacks/workflows/fixed/ must come out clean
# under the strictest persona, so we know the finding is about the attack and not about noise.
# This repository's own workflows must be clean too, under the same settings.
set -euo pipefail

ZIZMOR=${ZIZMOR:-zizmor}
OUT=${OUT:-test/out}
mkdir -p "$OUT"

findings() { # file -> sorted, unique audit names, one per line
  # zizmor exits non-zero when it finds something; the JSON is what we judge.
  $ZIZMOR --offline --pedantic -c zizmor.yml --format json "$@" 2>/dev/null |
    python3 -c 'import json, sys; print("\n".join(sorted({f["ident"] for f in json.load(sys.stdin)})))' || true
}

failed=0
rows=()
for attack in attacks/workflows/*.yml; do
  name=$(basename "$attack" .yml)
  expect=$(sed -n 's/^# expect: //p' "$attack")
  got=$(findings "$attack" | paste -sd, -)
  fixed=$(findings "attacks/workflows/fixed/$name.yml" | paste -sd, -)
  result=ok
  if [[ $got != "$expect" || -n $fixed ]]; then
    result=FAIL
    failed=1
  fi
  rows+=("| $name | $expect | ${got:-none} | ${fixed:-none} | $result |")
  printf '%-4s %-28s attack: %-24s fixed: %s\n' "$result" "$name" "${got:-none}" "${fixed:-none}"
done

own=$(findings .github/workflows | paste -sd, -)
if [[ -n $own ]]; then
  echo "FAIL this repository's own workflows: $own" >&2
  $ZIZMOR --offline --pedantic -c zizmor.yml .github/workflows >&2 || true
  failed=1
else
  echo "ok   own workflows: no findings"
fi

{
  echo "### Workflow attacks"
  echo
  echo "| attack | must be flagged by | flagged by | fixed version | result |"
  echo "|---|---|---|---|---|"
  printf '%s\n' "${rows[@]}"
  echo
  echo "Own workflows: ${own:-no findings}"
} >"$OUT/workflows.md"
[[ -n ${GITHUB_STEP_SUMMARY:-} ]] && cat "$OUT/workflows.md" >>"$GITHUB_STEP_SUMMARY"
exit $failed
