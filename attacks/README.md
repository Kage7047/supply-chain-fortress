# Attacks

Each attack is a test. The cluster attacks run in the `cluster attacks` CI job
([`test/attacks.sh`](../test/attacks.sh)), the dependency attacks in `dependency attacks`
([`test/deps.sh`](../test/deps.sh)), and the workflow attacks in `workflow attacks`
([`test/workflows.sh`](../test/workflows.sh)).

## Cluster attacks

Every pod goes through real admission with `kubectl apply --dry-run=server`. The "control" column
is the same attack in a namespace without that defence. It must be admitted, or the test proves
nothing.

| id | attack | defence that stops it | control |
|---|---|---|---|
| a01 | Deploy an image nobody signed | signature from `release.yml@refs/heads/main` | admitted with no policy |
| a02 | Sign and attest the image with your own key | the policy accepts one keyless identity, no keys | admitted with no policy |
| a03 | Correctly signed image without an SBOM attestation | SBOM attestation by the same identity | admitted with no policy |
| a04 | After the genuine image is verified, re-point its tag at your own image | verification resolves the tag to a digest every time, and the pod is rewritten to the digest it verified | admitted with no policy |
| a05 | Use an image from a different registry | registry allowlist (`ValidatingAdmissionPolicy`) | **admitted with the signature policy alone**: it only checks images that match its pattern |
| a06 | Genuine app container, unsigned init container | the validations check init and ephemeral containers too; `required: true` refuses any matched image no validation looked at | **admitted when the validations check only `images.containers` (as most examples do) and `required` is off**. With `required` on, the narrow policy still refuses it (a06n) |
| a07 | Image signed in CI, but by a pull request run of another workflow | the certificate identity names the release workflow and branch | admitted by the same policy with this run's identity |
| a08 | `kubectl debug` an admitted pod with an unsigned image | the policy matches the `pods/ephemeralcontainers` subresource, not only pods | **admitted by a policy that matches only `pods`**: the pod was verified once, the debug container never is |
| a09 | Kyverno is deployed but cannot answer (hung, overloaded, cut off), then deploy | `failurePolicy: Fail`: the API server refuses what it cannot check. The genuine image is refused too (p09): failing closed costs availability | **admitted with `failurePolicy: Ignore`** |
| a14 | Scale Kyverno to zero (an incident, a script, an autoscaler), or delete its Deployment (a14d) | a built-in `ValidatingAdmissionPolicy` evaluated by the API server itself ([`protect-kyverno.yaml`](../policy/protect-kyverno.yaml)) | **without it, the unsigned image is admitted even with `failurePolicy: Fail`** (c14): on the way down, Kyverno deletes its own webhooks |
| a15 | Delete Kyverno's webhook configurations (the other way to switch it off) | a second built-in policy: only Kyverno's own service account may change or delete them (ok6 checks Kyverno still can) | **without it, a cluster admin deletes them** (c15) |
| a13 | Put the unsigned image in a Deployment | autogen: Kyverno generates the same checks for Deployments, Jobs and the rest, so the Deployment is refused at `kubectl apply` | admitted with no policy |

Two of these were found by the tests failing. **a14:** the first version of a09 scaled Kyverno
to zero and expected `failurePolicy: Fail` to refuse the pod. It was admitted. Kyverno's last pod
deletes every Kyverno webhook configuration when its Deployment is scaled to zero or deleted
(`cleanup` in `pkg/webhooks/server.go`), so there is nothing left to fail. **a13:** autogen only
runs when a policy matches exactly `pods`. Matching `pods/ephemeralcontainers` too, which closes
a08, switched autogen off without a warning, so `kubectl debug` now has a policy of its own.
And the guard's own first version let `kubectl scale --replicas=0` through: a Scale object leaves
`replicas` out when it is zero, and the expression read a missing field as "not set".

Positive checks run first: the genuine image is admitted by digest, by tag (rewritten to its
digest), and through tag `v1` before a04 moves it; a Deployment of the genuine image is admitted
with its template rewritten to the digest (ok4).

## Kyverno's own images

Kyverno decides what runs, so a backdoored Kyverno makes every other check meaningless.
[`test/verify-kyverno.sh`](../test/verify-kyverno.sh) checks both of its images before
`cluster-up.sh` installs them, and the cluster then runs those digests and nothing else.
These attacks run in [`test/kyverno-trust.sh`](../test/kyverno-trust.sh).

Kyverno's release images carry SLSA provenance signed by
[slsa-github-generator](https://github.com/slsa-framework/slsa-github-generator)'s reusable
workflow (cosign v3.1.4 finds no plain signature on v1.19.2). The certificate's subject is
the generator, the same for every project that calls it. Who built the image is in two other claims:
the calling repository and its ref. The check pins both.

| id | attack | refused because | control that accepts it |
|---|---|---|---|
| a10 | Backdoored copy of Kyverno with Kyverno's real provenance document attached, signed keyless by the attacker's own GitHub workflow | the certificate subject is not the SLSA generator | "signed by some GitHub workflow" (`--certificate-identity-regexp '^https://github.com/'`) |
| a11 | Downgrade: a genuine Kyverno image from an older release (v1.18.2) | the workflow ref is not `refs/tags/v1.19.2` | the right repository, any tag |
| a12 | Another project's image, with genuine SLSA provenance from the same generator | the calling repository is not `kyverno/kyverno` | checking only the certificate subject |

Pinning the digest matters as much as the provenance: Kyverno's other images (`kyverno-cli`,
`background-controller`) have the same repository and tag in their provenance, so a check by
provenance alone would accept one of them in place of the admission controller.

## Dependency attacks

Go module paths are domain names, so npm-style dependency confusion (publish a public package
under the name of your private one) does not apply. These are the Go attacks that do.

The victim is a small module that depends on `rsc.io/quote v1.5.2`, a real public module kept for
demos. A local proxy serves the same version with a backdoor in `Hello()`. The defences are in
[`test/gocheck.sh`](../test/gocheck.sh): `env` runs before every step that fetches a Go module, and
`module` checks the app's go.mod and go.sum (the app has no dependencies, on purpose, so for now
that check guards the next one somebody adds). Every control runs the backdoor, except c04, where
the point is that nothing looks wrong.

| id | attack | refused by | control |
|---|---|---|---|
| d01 | The proxy serves a tampered copy of a version already in go.sum | go.sum: "does NOT match an earlier download" | **backdoor runs** with no go.sum line and the checksum database skipped |
| d02 | The same, for a version new to go.sum (`go get`, a version bump) | the checksum database (sum.golang.org) | **backdoor runs** with `GONOSUMDB=rsc.io` |
| d03 | A pull request changes the go.sum line to the tampered hash, and the proxy (a company proxy, a `GOPROXY` override) serves the tampered module | `gocheck.sh module`: go.sum is derived again from the checksum database, and every committed line must match | **backdoor runs with default settings**: the go command never asks the checksum database about a line that is already in go.sum |
| d04 | A lookalike module (here `rsc.io/quote/v3`), genuine and in the checksum database | the allowlist [`test/deps.allow`](../test/deps.allow) | `go build` and `go mod verify` accept it: checksums prove everyone got the same bytes, not that they are the bytes you meant. The real case: `github.com/boltdb-go/bolt`, a backdoored copy of boltdb/bolt that proxy.golang.org kept serving for three years (Socket, Feb 2025) |
| d05 | The job's settings switch the checksum database off: `GONOSUMDB`, `GOPRIVATE=*`, `GOSUMDB=off`, another `GOPROXY` | `gocheck.sh env`, in every job before Go fetches anything (CI lint, the release's `go install ko`) | **backdoor runs** with `GOSUMDB=off` |
| d06 | go.mod replaces the module with a directory in the repository | `gocheck.sh module` refuses `replace` | **backdoor runs with default settings**, the genuine proxy and the checksum database on: a directory has no go.sum line |
| d07 | The backdoor is edited into `vendor/` | `gocheck.sh module` refuses `vendor/` (and `go.work`, which can replace modules the same way) | **backdoor runs with default settings**, and `go mod verify` passes: Go builds from `vendor/` when it exists, and neither checks it against go.sum |

d03 is the one worth remembering. go.sum is trust on first use: it stops a proxy from changing
code you already have, but a go.sum change in a pull request is trusted the same way, and a
reviewer cannot tell a good hash from a bad one. d06 and d07 were found by an automated review
of the first version of the check, which only looked at go.sum.

## Workflow attacks

The file in `workflows/` must be flagged by the zizmor audit on its `# expect:` line; its fixed
version in `workflows/fixed/` must come out clean under `--pedantic`.

| id | attack | real incident | flagged by |
|---|---|---|---|
| w01 | Pwn request: `pull_request_target` checks out and runs the PR's code with the base repo's secrets | Ultralytics (Dec 2024), many smaller ones | `dangerous-triggers` |
| w02 | Script injection: `${{ github.event.pull_request.title }}` pasted into `run:` | the class GitHub Security Lab keeps finding in popular repos | `template-injection` |
| w03 | Action pinned to a tag, which its owner (or a thief) can move | tj-actions/changed-files (Mar 2025): every tag re-pointed at code that dumped secrets to logs | `unpinned-uses` (hash-pin required for every action) |
| w04 | `permissions: write-all` | every compromised action then holds a token that can push and release | `excessive-permissions` |
| w05 | Checkout persists the token in `.git/config`, then the workspace is uploaded as an artifact | "ArtiPACKED" (Palo Alto Unit 42, Aug 2024) | `artipacked` |

## Next

- Build tools installed at `@latest` (every `go install` and `go run` here pins a version, but nothing checks it)
- Registry allowlist for Deployments (the `ValidatingAdmissionPolicy` still checks only pods)
- Cache poisoning across workflows
