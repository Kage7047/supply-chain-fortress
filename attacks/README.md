# Attacks

Each attack is a test. The cluster attacks run in the `cluster attacks` CI job
([`test/attacks.sh`](../test/attacks.sh)); the workflow attacks run in `workflow attacks`
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

- Dependency confusion and `go.sum` tampering
- Registry allowlist for Deployments (the `ValidatingAdmissionPolicy` still checks only pods)
- Cache poisoning across workflows
