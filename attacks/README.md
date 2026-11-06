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
| a06 | Genuine app container, unsigned init container | the signature policy checks init and ephemeral containers too | **admitted by a policy that checks only `images.containers`**, as most examples do |
| a07 | Image signed in CI, but by a pull request run of another workflow | the certificate identity names the release workflow and branch | admitted by the same policy with this run's identity |

Positive checks run first: the genuine image is admitted by digest, by tag (rewritten to its
digest), and through tag `v1` before a04 moves it.

## Workflow attacks

The file in `workflows/` must be flagged by the zizmor audit on its `# expect:` line; its fixed
version in `workflows/fixed/` must come out clean under `--pedantic`.

| id | attack | real incident | flagged by |
|---|---|---|---|
| 08 | Pwn request: `pull_request_target` checks out and runs the PR's code with the base repo's secrets | Ultralytics (Dec 2024), many smaller ones | `dangerous-triggers` |
| 09 | Script injection: `${{ github.event.pull_request.title }}` pasted into `run:` | the class GitHub Security Lab keeps finding in popular repos | `template-injection` |
| 10 | Action pinned to a tag, which its owner (or a thief) can move | tj-actions/changed-files (Mar 2025): every tag re-pointed at code that dumped secrets to logs | `unpinned-uses` (hash-pin required for every action) |
| 11 | `permissions: write-all` | every compromised action then holds a token that can push and release | `excessive-permissions` |
| 12 | Checkout persists the token in `.git/config`, then the workspace is uploaded as an artifact | "ArtiPACKED" (Palo Alto Unit 42, Aug 2024) | `artipacked` |

## Next

- Ephemeral containers through `kubectl debug` (the `pods/ephemeralcontainers` subresource)
- Kyverno down: `failurePolicy: Fail` must refuse pods rather than let them through
- Verify Kyverno's own images before installing it
- Dependency confusion and `go.sum` tampering
- Cache poisoning across workflows
