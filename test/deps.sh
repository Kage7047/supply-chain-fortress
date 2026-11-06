#!/usr/bin/env bash
# Dependency attacks. A small victim module depends on rsc.io/quote v1.5.2 (a real public module,
# kept for demos like this). A local proxy serves the same version with a backdoor in Hello(),
# which makes the victim print "BACKDOOR". Each attack must be refused with the message of the
# defence meant to stop it, and its control (the same attack with that defence switched off) must
# run the backdoor.
#
# Go module paths are domain names, so npm-style dependency confusion (publish a public package
# under your private package's name) does not apply. What does: a tampered module on a proxy, an
# edited go.sum, settings that switch the checksum database off, and lookalike modules.
#
# Needs the network (proxy.golang.org and sum.golang.org).
set -euo pipefail

OUT=${OUT:-test/out}
mkdir -p "$OUT"
here=$(cd "$(dirname "$0")" && pwd)
work=$(mktemp -d)
trap 'chmod -R u+w "$work" 2>/dev/null; rm -rf "$work"' EXIT
MOD=rsc.io/quote
VER=v1.5.2

gox() { # gox <dir> [VAR=value...] -- <go args>: go with default settings and an empty module cache
  local dir=$1 vars=() cache
  shift
  while [[ $1 != -- ]]; do vars+=("$1"); shift; done
  shift
  cache=$(mktemp -d "$work/cache.XXXX")
  (cd "$dir" && env -u GOPROXY -u GOSUMDB -u GONOSUMDB -u GOPRIVATE -u GONOPROXY -u GOINSECURE -u GOFLAGS \
    GOENV=off GOFLAGS=-modcacherw GOMODCACHE="$cache" "${vars[@]}" go "$@")
}

victim() { # victim <name> <go.sum>: a copy of the victim module with that go.sum
  rm -rf "${work:?}/$1"
  cp -r "$work/victim" "$work/$1"
  cp "$2" "$work/$1/go.sum"
  echo "$work/$1"
}

# The victim, its genuine go.sum, and a module cache to build the attacker's proxy from.
mkdir "$work/victim"
cat >"$work/victim/main.go" <<'EOF'
package main

import (
	"fmt"

	"rsc.io/quote"
)

func main() { fmt.Println(quote.Hello()) }
EOF
gox "$work/victim" -- mod init example.com/victim 2>/dev/null
gox "$work/victim" GOMODCACHE="$work/genuine" -- get "$MOD@$VER" 2>/dev/null
cp "$work/victim/go.sum" "$work/sum.genuine"
grep -v "^$MOD $VER h1:" "$work/sum.genuine" >"$work/sum.new" # the version is not in go.sum yet
printf '%s\n' rsc.io/quote rsc.io/sampler golang.org/x/text >"$work/allow"

# The attacker's proxy: the genuine files, with the backdoor in the module zip. Its go.mod is
# untouched, so only the code differs. No sumdb directory: the go command asks sum.golang.org.
cp -r "$work/genuine/cache/download" "$work/evil"
rm -rf "$work/evil/sumdb"
python3 -I - "$work/evil/$MOD/@v/$VER.zip" <<'EOF'
import shutil, sys, zipfile
src = sys.argv[1]
old = b"func Hello() string {\n\treturn sampler.Hello()"
new = b'func Hello() string {\n\treturn "BACKDOOR " + sampler.Hello()'
changed = False
with zipfile.ZipFile(src) as zin, zipfile.ZipFile(src + ".new", "w", zipfile.ZIP_DEFLATED) as zout:
    for info in zin.infolist():
        data = zin.read(info)
        if info.filename.endswith("/quote.go"):
            assert old in data, "quote.go is not the expected v1.5.2 source"
            data, changed = data.replace(old, new), True
        zout.writestr(info.filename, data)
assert changed, "no quote.go in the module zip"
shutil.move(src + ".new", src)
EOF
EVIL=GOPROXY=file://$work/evil

# The go.sum an attacker would commit: the tampered module's hash, recorded the way go records any
# new module, with the checksum database out of the way.
dir=$(victim attacker "$work/sum.new")
gox "$dir" "$EVIL" GONOSUMDB=rsc.io -- run -mod=mod . >/dev/null 2>&1
cp "$dir/go.sum" "$work/sum.tampered"
cmp -s "$work/sum.genuine" "$work/sum.tampered" && { echo "FAIL the tampered module has the genuine hash" >&2; exit 1; }

# A lookalike: rsc.io/quote/v3 is a different module, genuine and in the checksum database, and not
# one the victim's owner chose. It stands in for a typosquat such as github.com/boltdb-go/bolt
# (Socket, Feb 2025: a backdoored copy of boltdb/bolt that proxy.golang.org served for three years).
mkdir "$work/lookalike"
cp "$work/victim/main.go" "$work/lookalike/"
sed -i 's|"rsc.io/quote"|quote "rsc.io/quote/v3"|; s|quote.Hello()|quote.HelloV3()|' "$work/lookalike/main.go"
gox "$work/lookalike" -- mod init example.com/victim 2>/dev/null
gox "$work/lookalike" -- get rsc.io/quote/v3@v3.1.0 2>/dev/null

verified_build() { # the go command's own checks on a module: build it, then go mod verify
  gox "$1" GOMODCACHE="$work/cache.verify" -- run . && gox "$1" GOMODCACHE="$work/cache.verify" -- mod verify
}

failed=0
rows=()
# check <id> <expect: genuine|refused|backdoor> <needle> <description> -- <command...>
check() {
  local id=$1 expect=$2 needle=$3 desc=$4 out rc result=ok got
  shift 5
  rc=0
  out=$("$@" 2>&1) || rc=$?
  if ((rc != 0)); then
    got=refused
  elif [[ $out == *BACKDOOR* ]]; then
    got=backdoor
  else
    got=genuine
  fi
  if [[ $got != "$expect" || ($expect == refused && $out != *"$needle"*) ]]; then
    result=FAIL
    failed=1
  fi
  printf '%-4s %-5s %-9s %s\n' "$result" "$id" "$got" "$desc"
  if [[ $result == FAIL ]]; then
    echo "     expected $expect${needle:+ with \"$needle\"}; output:" >&2
    sed 's/^/     | /' <<<"$out" | tail -15 >&2
  fi
  rows+=("| $id | $desc | $got | $result |")
}

GENUINE=$(victim genuine "$work/sum.genuine")
check ok1 genuine "" "genuine module from proxy.golang.org" \
  -- gox "$GENUINE" -- run .
check ok2 genuine "" "the module check passes the genuine go.sum" \
  -- "$here/gocheck.sh" module "$GENUINE" "$work/allow"

check d01 refused "does NOT match an earlier download recorded in go.sum" \
  "the proxy serves a tampered $MOD $VER; go.sum already has $VER" \
  -- gox "$(victim d01 "$work/sum.genuine")" "$EVIL" -- run .
check c01 backdoor "" "control: no go.sum line for $VER, checksum database skipped" \
  -- gox "$(victim c01 "$work/sum.new")" "$EVIL" GONOSUMDB=rsc.io -- run -mod=mod .

check d02 refused "does NOT match the one reported by the checksum server" \
  "the same, but $VER is new to go.sum (go get, a version bump)" \
  -- gox "$(victim d02 "$work/sum.new")" "$EVIL" -- run -mod=mod .
check c02 backdoor "" "control: GONOSUMDB=rsc.io (what GOPRIVATE and GONOSUMDB exemptions do)" \
  -- gox "$(victim c02 "$work/sum.new")" "$EVIL" GONOSUMDB=rsc.io -- run -mod=mod .

check d03 refused "is not what the checksum database has" \
  "a pull request changes go.sum to the tampered hash; the proxy serves the tampered module" \
  -- "$here/gocheck.sh" module "$(victim d03 "$work/sum.tampered")" "$work/allow"
check c03 backdoor "" "control: a plain go build accepts it (go never asks the checksum database about a line in go.sum)" \
  -- gox "$(victim c03 "$work/sum.tampered")" "$EVIL" -- run .

check d04 refused "is not on the allowlist" "a lookalike module (rsc.io/quote/v3), genuine everywhere" \
  -- "$here/gocheck.sh" module "$work/lookalike" "$work/allow"
check c04 genuine "" "control: go build and go mod verify accept the lookalike" \
  -- verified_build "$work/lookalike"

check d05 refused "skip the checksum database" "the job's settings exempt modules from the checksum database (GONOSUMDB)" \
  -- env GONOSUMDB=rsc.io "$here/gocheck.sh" env
check d05p refused "skip the checksum database" "... or GOPRIVATE=* (common in company setups)" \
  -- env GOPRIVATE='*' "$here/gocheck.sh" env
check d05o refused "must be sum.golang.org" "... or GOSUMDB=off" \
  -- env GOSUMDB=off "$here/gocheck.sh" env
check d05x refused "must come from proxy.golang.org" "... or GOPROXY points somewhere else" \
  -- env "$EVIL" "$here/gocheck.sh" env
check c05 backdoor "" "control: GOSUMDB=off, the tampered module runs" \
  -- gox "$(victim c05 "$work/sum.new")" "$EVIL" GOSUMDB=off -- run -mod=mod .
check ok3 genuine "" "the settings check passes this job's own settings" \
  -- "$here/gocheck.sh" env

{
  echo "### Dependency attacks"
  echo
  echo "| id | attack | outcome | result |"
  echo "|---|---|---|---|"
  printf '%s\n' "${rows[@]}"
} >"$OUT/deps.md"
[[ -n ${GITHUB_STEP_SUMMARY:-} ]] && cat "$OUT/deps.md" >>"$GITHUB_STEP_SUMMARY"
exit $failed
