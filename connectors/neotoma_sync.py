"""Sync Neotoma contacts into a Darkmesh node.

Reads entities (default: ``entity_type=contact``) from a Neotoma HTTP API,
maps them into the Darkmesh ingest shape, and posts them to the node at
``/darkmesh/ingest`` as ``contacts`` and ``interactions`` datasets. Follows
the pattern established by :mod:`connectors.openclaw_sync` and
:mod:`connectors.contacts_csv`.

Strength is derived from Neotoma's own signals (observation count,
recency, relationship count) rather than a cross-channel interaction
log, since Neotoma is the substrate, not a raw event stream.

Run with ``--dry-run`` to preview the mapped contacts and the computed
strength histogram without ingesting.
"""

from __future__ import annotations

import argparse
import json
import math
import os
import sys
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple

import requests

from connectors._auth import ConnectorAuth, add_auth_arguments


CONNECTOR_SUB_PREFIX = "connector-neotoma-sync"


def _default_connector_sub() -> str:
    operator = (
        os.environ.get("DARKMESH_NODE_ID")
        or os.environ.get("DARKMESH_OPERATOR")
        or "local"
    )
    return f"{CONNECTOR_SUB_PREFIX}@{operator}"


DEFAULT_NEOTOMA_URL = "http://localhost:3080"
DEFAULT_DARKMESH_URL = "http://localhost:8001"
DEFAULT_ENTITY_TYPE = "contact"

# Strength weights. Tuned so a frequently-observed, recently-touched contact
# with multiple typed relationships lands near 1.0 and a one-off entity near 0.
VOLUME_HALF_LIFE_OBSERVATIONS = 8.0
RELATIONSHIP_HALF_LIFE = 6.0
RECENCY_DECAY_DAYS = 45.0
STRENGTH_WEIGHTS = {
    "volume": 0.45,
    "relationships": 0.20,
    "recency": 0.35,
}


@dataclass
class NeotomaContact:
    entity_id: str
    name: str
    email: str
    org: str
    role: str
    observation_count: int
    relationship_count: int
    last_observation_at: Optional[datetime]

    def to_darkmesh_contact(self, strength: float) -> Dict[str, Any]:
        return {
            "name": self.name or self.email or self.entity_id,
            "email": self.email,
            "org": self.org,
            "role": self.role,
            "strength": round(strength, 3),
            "neotoma_entity_id": self.entity_id,
        }


def _pick_string(*values: Any) -> str:
    for value in values:
        if value is None:
            continue
        token = str(value).strip()
        if token:
            return token
    return ""


def _normalize_email(value: Any) -> str:
    token = _pick_string(value)
    return token.lower() if "@" in token else token.lower()


def _parse_timestamp(value: Any) -> Optional[datetime]:
    if value is None:
        return None
    if isinstance(value, (int, float)):
        ts = float(value)
        if ts > 1_000_000_000_000:
            ts /= 1000.0
        try:
            return datetime.fromtimestamp(ts, tz=timezone.utc)
        except (OverflowError, OSError, ValueError):
            return None
    raw = str(value).strip().replace("Z", "+00:00")
    if not raw:
        return None
    try:
        parsed = datetime.fromisoformat(raw)
    except ValueError:
        return None
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)


def _flatten_snapshot(entity: Dict[str, Any]) -> Dict[str, Any]:
    """Neotoma returns snapshot fields either at the top level or nested
    under ``snapshot``. Merge with snapshot winning, since it's the
    reducer-projected view.
    """
    snapshot = entity.get("snapshot") if isinstance(entity.get("snapshot"), dict) else {}
    merged: Dict[str, Any] = {}
    merged.update(entity)
    merged.update(snapshot or {})
    return merged


def _extract_observation_count(entity: Dict[str, Any]) -> int:
    for key in ("observation_count", "observations_count", "observations"):
        value = entity.get(key)
        if isinstance(value, int):
            return value
        if isinstance(value, list):
            return len(value)
    return 0


def _extract_relationship_count(entity: Dict[str, Any]) -> int:
    for key in ("relationship_count", "relationships_count"):
        value = entity.get(key)
        if isinstance(value, int):
            return value
    return 0


def _extract_last_observation_at(entity: Dict[str, Any]) -> Optional[datetime]:
    return _parse_timestamp(
        entity.get("last_observation_at")
        or entity.get("updated_at")
        or entity.get("last_seen_at")
    )


def map_entity_to_contact(entity: Dict[str, Any]) -> Optional[NeotomaContact]:
    merged = _flatten_snapshot(entity)
    entity_id = _pick_string(
        merged.get("entity_id"),
        merged.get("id"),
        entity.get("entity_id"),
        entity.get("id"),
    )
    if not entity_id:
        return None

    name = _pick_string(
        merged.get("canonical_name"),
        merged.get("name"),
        merged.get("full_name"),
        merged.get("display_name"),
    )
    email = _normalize_email(
        _pick_string(
            merged.get("email"),
            merged.get("primary_email"),
            merged.get("work_email"),
        )
    )
    org = _pick_string(
        merged.get("org"),
        merged.get("company"),
        merged.get("organization"),
        merged.get("current_company"),
        merged.get("employer"),
    )
    role = _pick_string(
        merged.get("role"),
        merged.get("title"),
        merged.get("job_title"),
    )

    return NeotomaContact(
        entity_id=entity_id,
        name=name,
        email=email,
        org=org,
        role=role,
        observation_count=_extract_observation_count(merged),
        relationship_count=_extract_relationship_count(merged),
        last_observation_at=_extract_last_observation_at(merged),
    )


def compute_strength(contact: NeotomaContact, now: datetime) -> float:
    """Map Neotoma provenance signals onto a 0.0-1.0 strength score.

    Mirrors the weighted structure in ``openclaw_sync.compute_strength`` but
    swaps the inputs: volume = observation count, bidirectionality is
    replaced by typed-relationship centrality, recency stays the same.
    """
    volume = 1.0 - math.exp(-max(0.0, contact.observation_count) / VOLUME_HALF_LIFE_OBSERVATIONS)
    relationships = 1.0 - math.exp(
        -max(0.0, contact.relationship_count) / RELATIONSHIP_HALF_LIFE
    )
    if contact.last_observation_at is None:
        recency = 0.0
    else:
        age_days = max(0.0, (now - contact.last_observation_at).total_seconds() / 86400.0)
        recency = math.exp(-age_days / RECENCY_DECAY_DAYS)

    score = (
        STRENGTH_WEIGHTS["volume"] * volume
        + STRENGTH_WEIGHTS["relationships"] * relationships
        + STRENGTH_WEIGHTS["recency"] * recency
    )
    return max(0.0, min(1.0, score))


def neotoma_headers(token: str) -> Dict[str, str]:
    headers = {"content-type": "application/json"}
    if token:
        headers["authorization"] = f"Bearer {token}"
    return headers


def fetch_entities(
    base_url: str,
    token: str,
    entity_type: str,
    limit: int,
    timeout: int,
) -> List[Dict[str, Any]]:
    url = f"{base_url.rstrip('/')}/entities/query"
    offset = 0
    collected: List[Dict[str, Any]] = []
    page_size = max(1, min(500, limit))
    while len(collected) < limit:
        payload = {
            "entity_type": entity_type,
            "limit": min(page_size, limit - len(collected)),
            "offset": offset,
            "include_snapshots": True,
        }
        resp = requests.post(url, json=payload, headers=neotoma_headers(token), timeout=timeout)
        resp.raise_for_status()
        body = resp.json() if resp.content else {}
        entities = body.get("entities") or body.get("results") or []
        if not entities:
            break
        collected.extend(entities)
        if len(entities) < payload["limit"]:
            break
        offset += len(entities)
    return collected[:limit]


def ingest_dataset(
    node_url: str,
    dataset: str,
    records: List[Dict[str, Any]],
    timeout: int,
    auth: ConnectorAuth,
) -> Dict[str, Any]:
    payload = {"dataset": dataset, "records": records}
    resp = auth.post(
        f"{node_url.rstrip('/')}/darkmesh/ingest",
        payload,
        timeout=timeout,
    )
    resp.raise_for_status()
    return resp.json()


def build_datasets(
    entities: Iterable[Dict[str, Any]],
    self_identifiers: Sequence[str],
    min_strength: float,
    max_contacts: int,
) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]], Dict[str, Any]]:
    self_set = {_normalize_email(ident) for ident in self_identifiers if ident}
    now = datetime.now(timezone.utc)

    scored: List[Tuple[float, NeotomaContact]] = []
    skipped = 0
    for entity in entities:
        contact = map_entity_to_contact(entity)
        if contact is None:
            skipped += 1
            continue
        if contact.email and contact.email in self_set:
            continue
        strength = compute_strength(contact, now)
        if strength < min_strength:
            continue
        scored.append((strength, contact))

    scored.sort(key=lambda item: item[0], reverse=True)
    scored = scored[:max_contacts]

    contacts: List[Dict[str, Any]] = []
    interactions: List[Dict[str, Any]] = []
    for strength, contact in scored:
        contacts.append(contact.to_darkmesh_contact(strength))
        if contact.email:
            interactions.append({"email": contact.email, "strength": round(strength, 3)})

    summary = {
        "entities_received": sum(1 for _ in entities) if isinstance(entities, list) else None,
        "contacts_mapped": len(contacts),
        "contacts_skipped": skipped,
        "interactions_prepared": len(interactions),
    }
    return contacts, interactions, summary


def main() -> None:
    parser = argparse.ArgumentParser(
        description=(
            "Sync Neotoma entities into a Darkmesh node as contacts and interactions."
        )
    )
    parser.add_argument("--url", default=DEFAULT_DARKMESH_URL, help="Darkmesh node URL")
    parser.add_argument(
        "--neotoma-url",
        default=os.environ.get("NEOTOMA_URL", DEFAULT_NEOTOMA_URL),
        help="Neotoma HTTP API base URL",
    )
    parser.add_argument(
        "--neotoma-token",
        default=os.environ.get("NEOTOMA_TOKEN", ""),
        help="Bearer token for Neotoma (or set NEOTOMA_TOKEN)",
    )
    parser.add_argument(
        "--entity-type",
        default=DEFAULT_ENTITY_TYPE,
        help="Neotoma entity_type to sync (default: contact)",
    )
    parser.add_argument(
        "--self-identifier",
        action="append",
        default=[],
        help="Identifiers to exclude from contacts (repeatable)",
    )
    parser.add_argument("--min-strength", type=float, default=0.05)
    parser.add_argument("--max-contacts", type=int, default=2000)
    parser.add_argument("--timeout", type=int, default=20)
    add_auth_arguments(parser, default_sub=_default_connector_sub())
    parser.add_argument("--dry-run", action="store_true")
    args = parser.parse_args()

    entities = fetch_entities(
        base_url=args.neotoma_url,
        token=args.neotoma_token,
        entity_type=args.entity_type,
        limit=max(1, args.max_contacts),
        timeout=args.timeout,
    )

    contacts, interactions, summary = build_datasets(
        entities=entities,
        self_identifiers=args.self_identifier,
        min_strength=max(0.0, min(1.0, args.min_strength)),
        max_contacts=max(1, args.max_contacts),
    )
    summary["entities_received"] = len(entities)
    summary["neotoma_url"] = args.neotoma_url
    summary["entity_type"] = args.entity_type

    if args.dry_run:
        preview = {
            "summary": summary,
            "top_contacts": contacts[:5],
        }
        print(json.dumps(preview, indent=2))
        return

    auth = ConnectorAuth.from_args(args, default_sub=_default_connector_sub())
    contacts_result = ingest_dataset(args.url, "contacts", contacts, args.timeout, auth)
    interactions_result = ingest_dataset(
        args.url, "interactions", interactions, args.timeout, auth
    )

    output = {
        "summary": summary,
        "ingest": {
            "contacts": contacts_result,
            "interactions": interactions_result,
        },
    }
    print(json.dumps(output, indent=2))


if __name__ == "__main__":
    try:
        main()
    except requests.HTTPError as exc:
        detail = ""
        try:
            detail = exc.response.text if exc.response is not None else ""
        except Exception:
            detail = ""
        print(f"HTTP error: {exc}\n{detail}", file=sys.stderr)
        sys.exit(1)
