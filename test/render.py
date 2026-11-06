#!/usr/bin/env python3
"""Render a test copy of a production policy.

The cluster tests run the real policy files with only the lines marked "# render: <key>" changed:
the registry (a local one instead of GHCR), the namespaces (one test namespace per variant), and,
when asked, the signer identity. Every requested change must find its marker, so editing the
production file in a way the tests no longer cover fails loudly instead of testing a lookalike.

    render.py policy/image-signatures.yaml --variant enforced --label fortress.test/images \\
        --registry fortress-registry:5000/fortress/ --subject https://github.com/... --insecure
"""

import argparse
import re
import sys

PROD_REGISTRY = "ghcr.io/kage7047/supply-chain-fortress/"
ALL_CONTAINERS = "(images.containers + images.initContainers + images.ephemeralContainers)"


def render(text: str, a: argparse.Namespace) -> str:
    used: set[str] = set()
    out = []
    for line in text.splitlines():
        m = re.search(r"# render: (\w+)\s*$", line)
        key = m.group(1) if m else None
        if key == "name":
            line = re.sub(r"(fortress-[a-z-]+)", rf"\1-{a.variant}", line, count=1)
        elif key == "namespaces":
            indent = line[: len(line) - len(line.lstrip())]
            line = f"{indent}- {{ key: {a.label}, operator: In, values: [{a.variant}] }}"
        elif key == "registry" and a.registry:
            line = line.replace(PROD_REGISTRY, a.registry)
        elif key == "insecure" and a.insecure:
            line = line.replace("allowInsecureRegistry: false", "allowInsecureRegistry: true")
        elif key == "subject" and a.subject:
            line = re.sub(r"subject: \S+", f"subject: {a.subject}", line)
        else:
            key = None
        if key:
            used.add(key)
        out.append(line)
    rendered = "\n".join(out) + "\n"

    wanted = {"name", "namespaces"}
    wanted |= {"registry"} if a.registry else set()
    wanted |= {"insecure"} if a.insecure else set()
    wanted |= {"subject"} if a.subject else set()
    if missing := wanted - used:
        sys.exit(f"render: no marker for {sorted(missing)} in {a.file}")
    if a.registry and PROD_REGISTRY in rendered:
        sys.exit(f"render: {PROD_REGISTRY} left on a line without a marker in {a.file}")

    if a.containers_only:
        # The control for attack 06: the policy as most examples write it.
        if ALL_CONTAINERS not in rendered:
            sys.exit("render: --containers-only found nothing to narrow")
        rendered = rendered.replace(ALL_CONTAINERS, "images.containers")
    return rendered


def main() -> None:
    p = argparse.ArgumentParser()
    p.add_argument("file")
    p.add_argument("--variant", required=True)
    p.add_argument("--label", required=True, help="namespace label that selects this variant")
    p.add_argument("--registry")
    p.add_argument("--subject")
    p.add_argument("--insecure", action="store_true")
    p.add_argument("--containers-only", action="store_true")
    a = p.parse_args()
    with open(a.file) as f:
        sys.stdout.write(render(f.read(), a))


if __name__ == "__main__":
    main()
