"""Idempotently append a public-JWK entry to a Darkmesh trust registry file.

Example::

    python scripts/darkmesh_trust_add.py \
        --public-jwk /path/to/anand_public.jwk.json \
        --sub darkmesh-node@anand \
        --iss https://darkmesh.local \
        --capabilities relay.register,relay.publish,relay.pull,node.callback.consent \
        --file config/trusted_agents.json

Pass ``--label "Anand's dev node"`` for a friendlier display name.

The script:

* computes the RFC 7638 thumbprint via :mod:`jwcrypto` so operators
  never need to cut/paste one;
* refuses to store anything that looks like a private JWK
  (``d``, ``p``, ``q``, ``dp``, ``dq``, ``qi``);
* loads existing entries through :func:`darkmesh.trust_registry`, so
  schema validation is identical to runtime loading;
* merges by thumbprint — passing the same JWK twice updates the
  sub / iss / capabilities in place rather than appending a duplicate;
* writes atomically via :func:`darkmesh.trust_registry.write_trust_registry`.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any, Dict, List

from jwcrypto import jwk


REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))


from darkmesh.trust_registry import (  # noqa: E402
    TrustRegistry,
    TrustRegistryError,
    write_trust_registry,
)


PRIVATE_JWK_FIELDS = ("d", "p", "q", "dp", "dq", "qi")


def _load_public_jwk(path: str) -> Dict[str, Any]:
    try:
        raw = Path(path).read_text(encoding="utf-8")
    except OSError as exc:
        raise SystemExit(f"cannot read public JWK at {path}: {exc}")
    try:
        parsed = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise SystemExit(f"public JWK at {path} is not valid JSON: {exc}")
    if not isinstance(parsed, dict):
        raise SystemExit(f"public JWK at {path} must be a JSON object")
    if any(k in parsed for k in PRIVATE_JWK_FIELDS):
        raise SystemExit(
            "refusing to add a trust entry that contains private-key "
            "material; extract just the public components first "
            "(e.g. jwk.export_public())"
        )
    return parsed


def _compute_thumbprint(public_jwk: Dict[str, Any]) -> str:
    try:
        key = jwk.JWK(**public_jwk)
    except Exception as exc:  # jwcrypto raises opaque types
        raise SystemExit(f"public JWK is not a valid RFC 7517 key: {exc}")
    return key.thumbprint()


def _parse_capabilities(raw: str) -> List[str]:
    if not raw:
        return []
    return [token.strip() for token in raw.split(",") if token.strip()]


def _existing_entries(registry_path: str) -> List[Dict[str, Any]]:
    target = Path(registry_path)
    if not target.exists():
        return []
    try:
        registry = TrustRegistry(registry_path, allow_missing=False)
    except TrustRegistryError as exc:
        raise SystemExit(f"existing trust file is malformed: {exc}")
    return registry.all_entries()


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument(
        "--public-jwk",
        required=True,
        help="Path to a JSON file containing the agent's public JWK",
    )
    parser.add_argument(
        "--sub",
        required=True,
        help="AAuth sub claim (e.g. darkmesh-node@anand, connector-csv-contacts@mark_local)",
    )
    parser.add_argument(
        "--iss",
        default="https://darkmesh.local",
        help="AAuth iss claim (default: https://darkmesh.local)",
    )
    parser.add_argument(
        "--capabilities",
        default="",
        help=(
            "Comma-separated capability list; defaults to none. Examples: "
            "relay.register,relay.publish,relay.pull,node.callback.consent"
        ),
    )
    parser.add_argument(
        "--label",
        default="",
        help="Optional display label for this entry (defaults to sub)",
    )
    parser.add_argument(
        "--file",
        required=True,
        help="Trust registry file to update (e.g. config/trusted_agents.json)",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Print the merged entry without writing",
    )
    args = parser.parse_args()

    public_jwk = _load_public_jwk(args.public_jwk)
    thumbprint = _compute_thumbprint(public_jwk)
    capabilities = _parse_capabilities(args.capabilities)

    new_entry: Dict[str, Any] = {
        "thumbprint": thumbprint,
        "sub": args.sub.strip(),
        "iss": args.iss.strip(),
        "public_jwk": public_jwk,
        "capabilities": capabilities,
    }
    if args.label:
        new_entry["label"] = args.label.strip()

    entries = _existing_entries(args.file)
    merged: List[Dict[str, Any]] = []
    replaced = False
    for entry in entries:
        if entry["thumbprint"] == thumbprint:
            merged.append(new_entry)
            replaced = True
        else:
            merged.append(entry)
    if not replaced:
        merged.append(new_entry)

    if args.dry_run:
        print(
            json.dumps(
                {
                    "file": args.file,
                    "thumbprint": thumbprint,
                    "action": "update" if replaced else "append",
                    "entry": new_entry,
                    "total_entries_after": len(merged),
                },
                indent=2,
            )
        )
        return

    try:
        write_trust_registry(args.file, merged)
    except TrustRegistryError as exc:
        raise SystemExit(f"refused to write trust file: {exc}")

    print(
        json.dumps(
            {
                "file": args.file,
                "thumbprint": thumbprint,
                "action": "update" if replaced else "append",
                "sub": new_entry["sub"],
                "iss": new_entry["iss"],
                "capabilities": capabilities,
                "total_entries": len(merged),
            },
            indent=2,
        )
    )


if __name__ == "__main__":
    main()
