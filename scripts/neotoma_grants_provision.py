"""Provision a Neotoma ``agent_grant`` for this Darkmesh node.

Bridges the gap left by Neotoma >= 0.9.0 (Stronger AAuth Admission release):
the ``NEOTOMA_AGENT_CAPABILITIES_*`` env-var registry has been removed and
admission is now driven entirely by first-class ``agent_grant`` entities.
This script reads the Darkmesh-side seed file (``config/neotoma_agent_capabilities.json``)
plus the running node's AAuth identity and creates / updates the matching
grant via Neotoma's REST API:

* ``GET /agents/grants?user_id=<id>`` to look up an existing grant by
  ``(match_sub, match_iss, match_thumbprint)``;
* ``POST /agents/grants`` to create a new grant on first run;
* ``PATCH /agents/grants/<grant_id>`` to update ``capabilities`` /
  ``label`` / ``match_*`` when the seed diverges from what is stored.

The script is **Bearer-bootstrapped** — first-run provisioning requires the
operator's user token (``NEOTOMA_TOKEN`` or ``--token-file``) because the
node's AAuth identity is not yet admitted; once a grant exists, regular
node traffic uses AAuth. We deliberately do not re-use the node's signing
key here: an AAuth-only path would chicken-and-egg for the very first
grant of a node.

Idempotency
-----------

A grant is matched by the ``(match_sub, match_iss, match_thumbprint)``
triple (any subset that is set in the seed must match exactly). On a
no-op rerun the script prints ``action: noop`` and exits 0. With
``--allow-update`` and a capability diff it prints ``action: update`` and
PATCHes; with ``--allow-create`` and no existing grant it prints
``action: create`` and POSTs. ``--dry-run`` short-circuits before any
network write.

Failure modes
-------------

* Bearer rejected by Neotoma (401/403): the script prints a one-line
  hint pointing the operator at the Inspector login page.
* ``404`` from ``/agents/grants``: the running Neotoma is older than the
  Stronger AAuth Admission release. The script prints an upgrade hint
  and exits non-zero rather than retrying with a different shape.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import requests


REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))


from darkmesh.aauth_signer import (  # noqa: E402
    SignerConfigError,
    jwk_thumbprint,
    load_signer_config_from_env,
)


DEFAULT_SEED_PATH = "config/neotoma_agent_capabilities.json"
DEFAULT_NEOTOMA_URL = os.environ.get("NEOTOMA_URL", "http://localhost:3080")
DEFAULT_LABEL_TEMPLATE = "Darkmesh node {sub}"


class ProvisionError(RuntimeError):
    """Raised on user-correctable provisioning errors."""


def _load_seed(path: str) -> Dict[str, Any]:
    seed_path = Path(path)
    if not seed_path.is_absolute():
        seed_path = REPO_ROOT / seed_path
    try:
        raw = seed_path.read_text(encoding="utf-8")
    except OSError as exc:
        raise ProvisionError(f"cannot read seed file {seed_path}: {exc}") from exc
    try:
        return json.loads(raw)
    except json.JSONDecodeError as exc:
        raise ProvisionError(
            f"seed file {seed_path} is not valid JSON: {exc}"
        ) from exc


def _resolve_seed_entry(seed: Dict[str, Any], sub: str) -> Dict[str, Any]:
    agents = seed.get("agents")
    if not isinstance(agents, dict):
        raise ProvisionError(
            "seed file is missing an `agents` object; see "
            "config/neotoma_agent_capabilities.json for the expected shape"
        )
    entry = agents.get(sub)
    if not isinstance(entry, dict):
        raise ProvisionError(
            f"seed file has no entry for sub={sub!r}; available keys: "
            f"{sorted(agents.keys())}"
        )
    capabilities = entry.get("capabilities")
    if not isinstance(capabilities, list) or not capabilities:
        raise ProvisionError(
            f"seed entry for sub={sub!r} is missing a non-empty "
            "`capabilities` list"
        )
    return entry


def _normalize_capabilities(raw: List[Any]) -> List[Dict[str, Any]]:
    """Sort entity_types per op so capability diffs are stable."""
    normalized: List[Dict[str, Any]] = []
    for entry in raw:
        if not isinstance(entry, dict):
            raise ProvisionError(
                f"capability entry is not an object: {entry!r}"
            )
        op = entry.get("op")
        types = entry.get("entity_types")
        if not isinstance(op, str) or not op:
            raise ProvisionError(f"capability entry missing `op`: {entry!r}")
        if not isinstance(types, list) or not all(isinstance(t, str) for t in types):
            raise ProvisionError(
                f"capability entry `entity_types` must be a list of strings: {entry!r}"
            )
        normalized.append({"op": op, "entity_types": sorted(types)})
    normalized.sort(key=lambda c: c["op"])
    return normalized


def _capability_diff(
    desired: List[Dict[str, Any]], existing: List[Dict[str, Any]]
) -> bool:
    return _normalize_capabilities(desired) != _normalize_capabilities(existing)


def _load_token(args: argparse.Namespace) -> str:
    if args.token_file:
        try:
            return Path(args.token_file).read_text(encoding="utf-8").strip()
        except OSError as exc:
            raise ProvisionError(
                f"cannot read --token-file {args.token_file}: {exc}"
            ) from exc
    token = os.environ.get("NEOTOMA_TOKEN")
    if token:
        return token.strip()
    raise ProvisionError(
        "no Bearer token provided. Set NEOTOMA_TOKEN or pass --token-file. "
        "Grab one from the Inspector login page on your Neotoma instance."
    )


def _bearer_headers(token: str) -> Dict[str, str]:
    return {
        "authorization": f"Bearer {token}",
        "accept": "application/json",
        "content-type": "application/json",
    }


def _check_bearer_rejection(response: requests.Response) -> None:
    if response.status_code in (401, 403):
        raise ProvisionError(
            f"Neotoma rejected the Bearer token (HTTP {response.status_code}). "
            "Verify NEOTOMA_TOKEN belongs to the user that owns this fleet; "
            "you can copy a fresh token from the Inspector login page."
        )


def _check_admission_404(response: requests.Response, route: str) -> None:
    if response.status_code == 404 and "/agents/grants" in route:
        raise ProvisionError(
            f"Neotoma at {response.url} returned 404 for {route}. The running "
            "Neotoma is older than the Stronger AAuth Admission release "
            "(>= 0.9.0). Upgrade Neotoma before provisioning grants — see "
            "docs/neotoma_integration.md `Upgrading from Neotoma <0.9 to >=0.9`."
        )


def _list_grants(
    base_url: str, headers: Dict[str, str], user_id: Optional[str]
) -> List[Dict[str, Any]]:
    params: Dict[str, Any] = {"status": "all"}
    if user_id:
        params["user_id"] = user_id
    response = requests.get(
        f"{base_url.rstrip('/')}/agents/grants",
        headers=headers,
        params=params,
        timeout=30,
    )
    _check_admission_404(response, "/agents/grants")
    _check_bearer_rejection(response)
    if response.status_code >= 400:
        raise ProvisionError(
            f"GET /agents/grants failed: HTTP {response.status_code} {response.text}"
        )
    payload = response.json()
    grants = payload.get("grants")
    if not isinstance(grants, list):
        raise ProvisionError(
            f"GET /agents/grants returned an unexpected payload: {payload!r}"
        )
    return grants


def _find_matching_grant(
    grants: List[Dict[str, Any]],
    match: Dict[str, Optional[str]],
) -> Optional[Dict[str, Any]]:
    """First grant whose set match_* fields all equal the desired values."""
    for grant in grants:
        if all(
            grant.get(field) == value
            for field, value in match.items()
            if value is not None
        ):
            if any(value is not None for value in match.values()):
                return grant
    return None


def _create_grant(
    base_url: str, headers: Dict[str, str], body: Dict[str, Any]
) -> Dict[str, Any]:
    response = requests.post(
        f"{base_url.rstrip('/')}/agents/grants",
        headers=headers,
        data=json.dumps(body),
        timeout=30,
    )
    _check_admission_404(response, "/agents/grants")
    _check_bearer_rejection(response)
    if response.status_code != 201:
        raise ProvisionError(
            f"POST /agents/grants failed: HTTP {response.status_code} {response.text}"
        )
    payload = response.json()
    grant = payload.get("grant")
    if not isinstance(grant, dict):
        raise ProvisionError(
            f"POST /agents/grants returned an unexpected payload: {payload!r}"
        )
    return grant


def _update_grant(
    base_url: str,
    headers: Dict[str, str],
    grant_id: str,
    body: Dict[str, Any],
) -> Dict[str, Any]:
    response = requests.patch(
        f"{base_url.rstrip('/')}/agents/grants/{grant_id}",
        headers=headers,
        data=json.dumps(body),
        timeout=30,
    )
    _check_admission_404(response, f"/agents/grants/{grant_id}")
    _check_bearer_rejection(response)
    if response.status_code != 200:
        raise ProvisionError(
            f"PATCH /agents/grants/{grant_id} failed: HTTP {response.status_code} {response.text}"
        )
    payload = response.json()
    grant = payload.get("grant")
    if not isinstance(grant, dict):
        raise ProvisionError(
            f"PATCH /agents/grants/{grant_id} returned an unexpected payload: {payload!r}"
        )
    return grant


def _build_desired(
    seed_entry: Dict[str, Any],
    sub: str,
    iss: str,
    thumbprint: str,
    label_override: Optional[str],
) -> Tuple[Dict[str, Any], Dict[str, Optional[str]], List[Dict[str, Any]]]:
    seed_match = seed_entry.get("match") or {}
    match: Dict[str, Optional[str]] = {
        "match_sub": seed_match.get("sub") or sub,
        "match_iss": seed_match.get("iss") or iss,
        "match_thumbprint": seed_match.get("thumbprint") or thumbprint,
    }
    capabilities = _normalize_capabilities(seed_entry["capabilities"])
    label = label_override or seed_entry.get("label") or DEFAULT_LABEL_TEMPLATE.format(sub=sub)
    body: Dict[str, Any] = {
        "label": label,
        "capabilities": capabilities,
        "match_sub": match["match_sub"],
        "match_iss": match["match_iss"],
        "match_thumbprint": match["match_thumbprint"],
    }
    if seed_entry.get("notes"):
        body["notes"] = seed_entry["notes"]
    return body, match, capabilities


def provision(
    *,
    seed_path: str,
    base_url: str,
    token: str,
    sub: str,
    iss: str,
    thumbprint: str,
    user_id: Optional[str],
    label_override: Optional[str],
    allow_create: bool,
    allow_update: bool,
    dry_run: bool,
) -> Dict[str, Any]:
    """Plan and (optionally) apply the grant for this node.

    Returned dict shape::

        {
            "action": "noop" | "create" | "update",
            "grant_id": str | None,
            "match": {...},
            "diff": {...},  # only when action == update
            "applied": bool,
        }
    """
    seed = _load_seed(seed_path)
    seed_entry = _resolve_seed_entry(seed, sub)
    desired_body, match, desired_caps = _build_desired(
        seed_entry, sub, iss, thumbprint, label_override
    )
    headers = _bearer_headers(token)
    grants = _list_grants(base_url, headers, user_id)
    existing = _find_matching_grant(grants, match)

    if existing is None:
        plan: Dict[str, Any] = {
            "action": "create",
            "grant_id": None,
            "match": match,
            "label": desired_body["label"],
            "capabilities": desired_caps,
            "applied": False,
        }
        if dry_run or not allow_create:
            return plan
        created = _create_grant(base_url, headers, desired_body)
        plan["grant_id"] = created.get("grant_id")
        plan["applied"] = True
        return plan

    existing_caps = _normalize_capabilities(existing.get("capabilities") or [])
    label_changed = (existing.get("label") or "") != desired_body["label"]
    match_changed = any(
        existing.get(field) != desired_body.get(field)
        for field in ("match_sub", "match_iss", "match_thumbprint")
    )
    caps_changed = _capability_diff(desired_caps, existing_caps)

    if not (label_changed or match_changed or caps_changed):
        return {
            "action": "noop",
            "grant_id": existing.get("grant_id"),
            "match": match,
            "applied": True,
        }

    diff: Dict[str, Any] = {}
    if label_changed:
        diff["label"] = {"from": existing.get("label"), "to": desired_body["label"]}
    if match_changed:
        diff["match"] = {
            "from": {
                k: existing.get(k) for k in ("match_sub", "match_iss", "match_thumbprint")
            },
            "to": match,
        }
    if caps_changed:
        diff["capabilities"] = {"from": existing_caps, "to": desired_caps}

    plan = {
        "action": "update",
        "grant_id": existing.get("grant_id"),
        "match": match,
        "diff": diff,
        "applied": False,
    }
    if dry_run or not allow_update:
        return plan
    update_body: Dict[str, Any] = {"capabilities": desired_caps}
    if label_changed:
        update_body["label"] = desired_body["label"]
    if match_changed:
        update_body["match_sub"] = match["match_sub"]
        update_body["match_iss"] = match["match_iss"]
        update_body["match_thumbprint"] = match["match_thumbprint"]
    if "notes" in desired_body:
        update_body["notes"] = desired_body["notes"]
    _update_grant(base_url, headers, existing["grant_id"], update_body)
    plan["applied"] = True
    return plan


def _identity_from_env() -> Tuple[str, str, str]:
    try:
        cfg = load_signer_config_from_env()
    except SignerConfigError as exc:
        raise ProvisionError(
            f"cannot derive AAuth identity from environment: {exc}"
        ) from exc
    return cfg.sub, cfg.iss, jwk_thumbprint(cfg.private_jwk)


def _build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument(
        "--seed",
        default=DEFAULT_SEED_PATH,
        help=f"Seed file (default: {DEFAULT_SEED_PATH})",
    )
    parser.add_argument(
        "--neotoma-url",
        default=DEFAULT_NEOTOMA_URL,
        help=f"Neotoma base URL (default: {DEFAULT_NEOTOMA_URL})",
    )
    parser.add_argument(
        "--token-file",
        help="Path to a file containing the operator's Bearer token (overrides NEOTOMA_TOKEN)",
    )
    parser.add_argument(
        "--user-id",
        help="Optional explicit owner user_id (defaults to the user the token authenticates as)",
    )
    parser.add_argument(
        "--sub",
        help="Override the AAuth sub (defaults to DARKMESH_AAUTH_SUB)",
    )
    parser.add_argument(
        "--iss",
        help="Override the AAuth iss (defaults to DARKMESH_AAUTH_ISS or https://darkmesh.local)",
    )
    parser.add_argument(
        "--thumbprint",
        help="Override the JWK thumbprint (defaults to RFC 7638 thumbprint of DARKMESH_AAUTH_PRIVATE_JWK)",
    )
    parser.add_argument(
        "--label",
        help="Display label for the grant (defaults to seed entry `label` or 'Darkmesh node <sub>')",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Plan only; never POST/PATCH",
    )
    parser.add_argument(
        "--allow-create",
        action="store_true",
        help="Allow POST to create a new grant when no match exists",
    )
    parser.add_argument(
        "--allow-update",
        action="store_true",
        help="Allow PATCH to update an existing grant when capabilities/label diverge",
    )
    parser.add_argument(
        "--auto",
        action="store_true",
        help="Shortcut for --allow-create --allow-update; intended for CI / fleet automation",
    )
    return parser


def main(argv: Optional[List[str]] = None) -> int:
    parser = _build_arg_parser()
    args = parser.parse_args(argv)
    allow_create = args.allow_create or args.auto
    allow_update = args.allow_update or args.auto

    try:
        env_sub, env_iss, env_thumb = _identity_from_env()
        sub = args.sub or env_sub
        iss = args.iss or env_iss
        thumbprint = args.thumbprint or env_thumb
        token = _load_token(args)
        result = provision(
            seed_path=args.seed,
            base_url=args.neotoma_url,
            token=token,
            sub=sub,
            iss=iss,
            thumbprint=thumbprint,
            user_id=args.user_id,
            label_override=args.label,
            allow_create=allow_create,
            allow_update=allow_update,
            dry_run=args.dry_run,
        )
    except ProvisionError as exc:
        print(json.dumps({"error": str(exc)}, indent=2), file=sys.stderr)
        return 2

    print(
        json.dumps(
            {
                "neotoma_url": args.neotoma_url,
                "sub": sub,
                "iss": iss,
                "thumbprint": thumbprint,
                **result,
            },
            indent=2,
        )
    )
    if result["action"] in ("create", "update") and not result["applied"]:
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
