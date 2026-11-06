# supply-chain-fortress

[![ci](https://github.com/Kage7047/supply-chain-fortress/actions/workflows/ci.yml/badge.svg)](https://github.com/Kage7047/supply-chain-fortress/actions/workflows/ci.yml)
[![release](https://github.com/Kage7047/supply-chain-fortress/actions/workflows/release.yml/badge.svg)](https://github.com/Kage7047/supply-chain-fortress/actions/workflows/release.yml)
![license](https://img.shields.io/badge/license-MIT-green)

A software supply chain where every defence has an attack that proves it works.

The repository ships one small Go service. Between its source and a running pod, the image is
built from pinned inputs, pushed by digest, signed keyless by one specific workflow, given an
attested SBOM and SLSA provenance, and admitted by Kubernetes only if all of that checks out.

Next to the defences is a folder of [attacks](attacks/README.md): real techniques from real
incidents (re-pointed tags, pwn requests, script injection, attacker-signed images, init-container
side doors). CI runs every one of them, on every pull request, against the production policy files.
Each attack is checked three ways, the same way [faultline](https://github.com/Kage7047/faultline)
checks its Raft:

1. **The genuine image is admitted.** A policy that refuses everything passes every attack test,
   so the first check is that the real thing gets through, and is pinned to its verified digest.
2. **The attack is refused, for the right reason.** The refusal has to carry the message of the
   defence meant to stop it, not just any error.
3. **The control: without that defence, the same attack is admitted.** This proves the attack is
   real and that this defence, not an accident of the test, is what stops it.

## The pipeline

```
 source ──► ko build ──► ghcr.io/…/app@sha256:… ──► cosign sign (keyless, Fulcio + Rekor)
 (pinned       (base image                          cosign attest SBOM (SPDX)
  actions,      by digest,                          GitHub build provenance (SLSA)
  hash-pinned   -trimpath)                                     │
  tools)                                                       ▼
                                Kubernetes admission ◄── pod spec
                                ├─ ValidatingAdmissionPolicy: image must come from this registry path
                                └─ Kyverno ImageValidatingPolicy:
                                     signed by release.yml on refs/heads/main, SBOM attested by the
                                     same identity, tag rewritten to the verified digest
```

- [`release.yml`](.github/workflows/release.yml) is the only workflow whose signature counts. The
  policy names it, and its branch, in the certificate identity. A signature from a pull request,
  another workflow in this repository, or a fork is refused (attack a07).
- [`policy/image-signatures.yaml`](policy/image-signatures.yaml) checks containers, init containers
  and ephemeral containers, including ones added later with `kubectl debug`. Most examples check
  only `images.containers` and match only `pods` (attacks a06, a08).
- [`policy/allowed-registries.yaml`](policy/allowed-registries.yaml) exists because the signature
  policy only looks at images matching its pattern. An image from anywhere else is not
  "unsigned", it is unexamined (attack a05).
- Every action is pinned to a commit SHA, every downloaded tool to a checksum, every image to a
  digest, Kyverno's Helm chart included. zizmor runs in its strictest persona on the repository's
  own workflows and must find nothing.

## Run it

The cluster tests sign images keyless with GitHub's OIDC token, so they run in Actions (see the
`cluster attacks` job's summary for the table). The workflow attacks run anywhere:

```bash
pip install --require-hashes --no-deps -r test/requirements.txt
test/workflows.sh
```

Verify a released image yourself:

```bash
cosign verify ghcr.io/kage7047/supply-chain-fortress/app:<commit sha> \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  --certificate-identity https://github.com/Kage7047/supply-chain-fortress/.github/workflows/release.yml@refs/heads/main
gh attestation verify oci://ghcr.io/kage7047/supply-chain-fortress/app:<commit sha> -R Kage7047/supply-chain-fortress
```

## Layout

| path | what |
|---|---|
| `app/` | the service being shipped |
| `policy/` | production admission policies, applied unmodified by the release check |
| `attacks/` | the attack catalogue; workflow attacks and their fixed versions |
| `test/cluster-up.sh` | kind + local registry + Kyverno, all pinned |
| `test/images.sh` | builds the genuine image and one image per cluster attack |
| `test/attacks.sh` | runs every cluster attack and its control |
| `test/render.py` | makes test copies of the production policies, changing only marked lines |
| `test/admit.sh` | proves the unmodified policies admit the real release |
| `test/workflows.sh` | runs zizmor on each workflow attack, its fix, and this repo's workflows |

## Not covered yet

Kyverno's own images are pulled by tag inside its chart, so the verifier is not yet verified;
Deployments are refused only when they create pods (no policy on the controller objects);
dependency confusion and build-cache poisoning have no attack yet.
