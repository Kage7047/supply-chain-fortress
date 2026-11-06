#!/usr/bin/env bash
# The Go dependency defences. Run them before anything fetches a module.
#
#   test/gocheck.sh env                        the go command's settings keep the checksum database on
#   test/gocheck.sh module <dir> <allowlist>   every dependency is on the allowlist, and every go.sum
#                                              line is what the checksum database has
#
# go.sum is trust on first use: once a line is in it, the go command never asks the checksum
# database about that module again. A pull request that edits a go.sum line, plus a proxy that
# serves the matching tampered code, builds cleanly (attack d03). So the module check throws go.sum
# away, derives it again from the checksum database, and requires every committed line to match.
set -euo pipefail

checksum_env() { # the settings the go.sum derivation runs with, whatever the caller's are
  env -u GONOSUMDB -u GOPRIVATE -u GONOPROXY -u GOINSECURE -u GOFLAGS \
    GOENV=off GOPROXY=https://proxy.golang.org,direct GOSUMDB=sum.golang.org GOFLAGS=-modcacherw "$@"
}

check_env() {
  local problems=() v
  [[ $(go env GOSUMDB) == sum.golang.org ]] ||
    problems+=("GOSUMDB=$(go env GOSUMDB): the checksum database must be sum.golang.org")
  for v in GONOSUMDB GOPRIVATE; do
    [[ -z $(go env "$v") ]] ||
      problems+=("$v=$(go env "$v"): modules matching it skip the checksum database")
  done
  [[ -z $(go env GOINSECURE) ]] ||
    problems+=("GOINSECURE=$(go env GOINSECURE): modules matching it are fetched without TLS checks")
  [[ $(go env GOPROXY) == https://proxy.golang.org,direct ]] ||
    problems+=("GOPROXY=$(go env GOPROXY): modules must come from proxy.golang.org")
  for v in $(go env GOFLAGS); do
    case $v in
      -mod=mod) problems+=("GOFLAGS has -mod=mod: the build may add modules and go.sum lines") ;;
      -insecure) problems+=("GOFLAGS has -insecure: modules are fetched without TLS checks") ;;
    esac
  done
  if ((${#problems[@]})); then
    printf 'go settings switch off a dependency check: %s\n' "${problems[@]}" >&2
    return 1
  fi
  echo "ok   go settings: checksum database on, proxy.golang.org, no exemptions"
}

check_module() {
  local dir=${1:?usage: gocheck.sh module <dir> <allowlist>} allow=${2:?usage: gocheck.sh module <dir> <allowlist>}
  local work cache mods path line bad=0
  work=$(mktemp -d)
  cache=$(mktemp -d)
  # shellcheck disable=SC2064 # expand now: the paths are local
  trap "rm -rf '$work' '$cache'" EXIT

  # 1. Every module in the build must be one somebody chose. A lookalike module is genuine as far
  #    as go.sum and the checksum database can tell: they prove everyone got the same bytes, not
  #    that the bytes are the ones you meant (attack d04).
  mods=$(cd "$dir" && checksum_env GOMODCACHE="$cache" go list -m -f '{{if not .Main}}{{.Path}}{{end}}' all)
  while read -r path; do
    [[ -n $path ]] || continue
    if ! grep -qxF "$path" <(sed 's/#.*//; s/[[:space:]]//g; /^$/d' "$allow"); then
      echo "module $path is not on the allowlist ($allow)" >&2
      bad=1
    fi
  done <<<"$mods"
  ((bad == 0)) || return 1

  # 2. Every go.sum line must be the checksum database's (attack d03).
  if [[ ! -f $dir/go.sum ]]; then
    echo "ok   $dir: no dependencies"
    return 0
  fi
  tar -C "$dir" --exclude=.git -cf - . | tar -C "$work" -xf -
  rm "$work/go.sum"
  (cd "$work" && checksum_env GOMODCACHE="$cache" go mod tidy) >&2
  while read -r line; do
    if ! grep -qxF "$line" "$work/go.sum"; then
      echo "go.sum line is not what the checksum database has: $line" >&2
      bad=1
    fi
  done <"$dir/go.sum"
  ((bad == 0)) || return 1
  echo "ok   $dir: $(wc -l <"$dir/go.sum") go.sum lines match the checksum database, all modules allowed"
}

case ${1:-} in
  env) check_env ;;
  module) shift; check_module "$@" ;;
  *) echo "usage: gocheck.sh env | module <dir> <allowlist>" >&2; exit 2 ;;
esac
