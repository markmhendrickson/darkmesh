import argparse
import csv
import json
import math
import os
import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Sequence, Set, Tuple
from urllib.parse import urlencode

import requests


DEFAULT_CHANNEL_WEIGHTS: Dict[str, float] = {
    "gmail": 1.0,
    "email": 1.0,
    "sms": 0.9,
    "whatsapp": 0.95,
    "telegram": 0.85,
    "slack": 0.75,
    "calendar": 0.8,
    "phone": 0.9,
    "unknown": 0.7,
}


@dataclass
class InteractionStats:
    identifier: str
    name: str = ""
    org: str = ""
    role: str = ""
    total_weight: float = 0.0
    inbound_weight: float = 0.0
    outbound_weight: float = 0.0
    channels: Set[str] = field(default_factory=set)
    latest_ts: Optional[datetime] = None


@dataclass
class InteractionEvent:
    identifier: str
    direction: str
    channel: str
    timestamp: Optional[datetime]
    name: str = ""
    org: str = ""
    role: str = ""


@dataclass
class SourceRef:
    source_id: str
    name: str
    provider: str


def normalize_identifier(value: Any) -> str:
    if value is None:
        return ""
    raw = str(value).strip()
    if not raw:
        return ""

    lowered = raw.lower()
    if "@" in lowered:
        return lowered
    if lowered.startswith("phone:"):
        digits = re.sub(r"[^0-9+]", "", lowered.removeprefix("phone:"))
        return f"phone:{digits}" if digits else ""
    if lowered.startswith("id:"):
        token = lowered.removeprefix("id:").strip()
        return f"id:{token}" if token else ""

    digits = re.sub(r"[^0-9+]", "", lowered)
    digit_count = len(re.sub(r"\D", "", digits))
    if digit_count >= 7:
        return f"phone:{digits}"

    if ":" in lowered:
        return lowered
    return ""


def pick_first_non_empty(values: Sequence[Any]) -> str:
    for value in values:
        if value is None:
            continue
        token = str(value).strip()
        if token:
            return token
    return ""


def normalize_name_token(value: str) -> str:
    return value.strip().lower()


def parse_timestamp(value: Any) -> Optional[datetime]:
    if value is None:
        return None

    if isinstance(value, (int, float)):
        ts = float(value)
        if ts > 1_000_000_000_000:
            ts = ts / 1000.0
        try:
            return datetime.fromtimestamp(ts, tz=timezone.utc)
        except (OverflowError, OSError, ValueError):
            return None

    raw = str(value).strip()
    if not raw:
        return None

    raw = raw.replace("Z", "+00:00")
    try:
        parsed = datetime.fromisoformat(raw)
    except ValueError:
        return None

    if parsed.tzinfo is None:
        return parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def detect_channel(record: Dict[str, Any]) -> str:
    value = pick_first_non_empty(
        [
            record.get("channel"),
            record.get("integration"),
            record.get("provider"),
            record.get("source"),
            record.get("type"),
        ]
    ).lower()

    if not value:
        return "unknown"
    if "gmail" in value or "email" in value:
        return "gmail"
    if "whatsapp" in value:
        return "whatsapp"
    if "sms" in value or "twilio" in value or "text" in value:
        return "sms"
    if "calendar" in value or "meeting" in value:
        return "calendar"
    if "slack" in value:
        return "slack"
    if "telegram" in value:
        return "telegram"
    if "call" in value or "phone" in value:
        return "phone"
    return value


def parse_headers(values: Sequence[str]) -> Dict[str, str]:
    headers: Dict[str, str] = {}
    for raw in values:
        if "=" not in raw:
            continue
        key, value = raw.split("=", 1)
        key = key.strip()
        value = value.strip()
        if key:
            headers[key] = value
    return headers


def parse_channel_weights(values: Sequence[str]) -> Dict[str, float]:
    weights = dict(DEFAULT_CHANNEL_WEIGHTS)
    for raw in values:
        if "=" not in raw:
            continue
        key, value = raw.split("=", 1)
        key = key.strip().lower()
        if not key:
            continue
        try:
            parsed = float(value.strip())
        except ValueError:
            continue
        weights[key] = max(0.0, parsed)
    return weights


def combine_url(base_url: str, path_or_url: str) -> str:
    value = path_or_url.strip()
    if value.startswith("http://") or value.startswith("https://"):
        return value
    return f"{base_url.rstrip('/')}/{value.lstrip('/')}"


def with_query(url: str, query: Dict[str, str]) -> str:
    if not query:
        return url
    return f"{url}?{urlencode(query)}"


def extract_record_list(payload: Any) -> List[Dict[str, Any]]:
    if isinstance(payload, list):
        return [item for item in payload if isinstance(item, dict)]
    if not isinstance(payload, dict):
        return []

    direct_keys = ["events", "records", "items", "messages", "data", "results"]
    for key in direct_keys:
        value = payload.get(key)
        if isinstance(value, list):
            return [item for item in value if isinstance(item, dict)]

    data_obj = payload.get("data")
    if isinstance(data_obj, dict):
        for key in ["events", "records", "items", "messages", "results"]:
            value = data_obj.get(key)
            if isinstance(value, list):
                return [item for item in value if isinstance(item, dict)]

    if payload:
        return [payload]
    return []


def extract_integration_items(payload: Any) -> List[Dict[str, Any]]:
    if isinstance(payload, list):
        return [item for item in payload if isinstance(item, dict)]

    if not isinstance(payload, dict):
        return []

    candidates: List[Dict[str, Any]] = []

    for key in ["integrations", "sources", "connectors", "items", "data", "results"]:
        value = payload.get(key)
        if isinstance(value, list):
            candidates.extend(item for item in value if isinstance(item, dict))
        elif isinstance(value, dict):
            for subkey in ["integrations", "sources", "connectors", "items", "results"]:
                nested = value.get(subkey)
                if isinstance(nested, list):
                    candidates.extend(item for item in nested if isinstance(item, dict))

    if not candidates:
        candidates.extend(extract_record_list(payload))

    return candidates


def load_records_from_file(path: str) -> List[Dict[str, Any]]:
    content = Path(path).read_text(encoding="utf-8")
    trimmed = content.strip()
    if not trimmed:
        return []

    if "\n" in trimmed and not trimmed.startswith("["):
        records: List[Dict[str, Any]] = []
        for line in trimmed.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                parsed = json.loads(line)
            except json.JSONDecodeError:
                continue
            if isinstance(parsed, dict):
                records.append(parsed)
        if records:
            return records

    payload = json.loads(trimmed)
    return extract_record_list(payload)


def load_records_from_url(url: str, headers: Dict[str, str], timeout: int) -> List[Dict[str, Any]]:
    resp = requests.get(url, headers=headers, timeout=timeout)
    resp.raise_for_status()
    payload = resp.json()
    return extract_record_list(payload)


def parse_participant(value: Any) -> Tuple[str, str, str, str]:
    if value is None:
        return "", "", "", ""

    if isinstance(value, str):
        return normalize_identifier(value), "", "", ""

    if not isinstance(value, dict):
        return "", "", "", ""

    identifier = normalize_identifier(
        pick_first_non_empty(
            [
                value.get("identifier"),
                value.get("email"),
                value.get("phone"),
                value.get("id"),
                value.get("user_id"),
                value.get("address"),
            ]
        )
    )

    name = pick_first_non_empty([value.get("name"), value.get("full_name"), value.get("display_name")])
    org = pick_first_non_empty([value.get("org"), value.get("company"), value.get("organization")])
    role = pick_first_non_empty([value.get("role"), value.get("title")])
    return identifier, name, org, role


def to_list(value: Any) -> List[Any]:
    if value is None:
        return []
    if isinstance(value, list):
        return value
    return [value]


def identify_event_direction(record: Dict[str, Any], sender_id: str, self_ids: Set[str]) -> str:
    explicit = str(record.get("direction", "")).strip().lower()
    if explicit in {"inbound", "incoming", "received"}:
        return "inbound"
    if explicit in {"outbound", "outgoing", "sent"}:
        return "outbound"

    if sender_id and sender_id in self_ids:
        return "outbound"
    if sender_id and sender_id not in self_ids:
        return "inbound"
    return "unknown"


def event_to_interactions(record: Dict[str, Any], self_ids: Set[str]) -> List[InteractionEvent]:
    channel = detect_channel(record)
    timestamp = parse_timestamp(
        pick_first_non_empty(
            [
                record.get("timestamp"),
                record.get("ts"),
                record.get("created_at"),
                record.get("occurred_at"),
                record.get("date"),
            ]
        )
    )

    direct_identifier = normalize_identifier(
        pick_first_non_empty(
            [
                record.get("counterparty_id"),
                record.get("counterparty"),
                record.get("identifier"),
                record.get("email"),
                record.get("phone"),
                record.get("person_id"),
            ]
        )
    )

    direct_name = pick_first_non_empty(
        [record.get("counterparty_name"), record.get("name"), record.get("person_name")]
    )
    direct_org = pick_first_non_empty([record.get("org"), record.get("company"), record.get("organization")])
    direct_role = pick_first_non_empty([record.get("role"), record.get("title")])

    if direct_identifier:
        direction = identify_event_direction(record, "", self_ids)
        return [
            InteractionEvent(
                identifier=direct_identifier,
                direction=direction,
                channel=channel,
                timestamp=timestamp,
                name=direct_name,
                org=direct_org,
                role=direct_role,
            )
        ]

    sender_id, sender_name, sender_org, sender_role = parse_participant(record.get("from") or record.get("sender"))
    to_participants = []
    for key in ["to", "cc", "bcc", "recipients", "participants"]:
        for raw in to_list(record.get(key)):
            parsed = parse_participant(raw)
            if parsed[0]:
                to_participants.append(parsed)

    direction = identify_event_direction(record, sender_id, self_ids)
    interactions: List[InteractionEvent] = []

    if direction == "inbound" and sender_id and sender_id not in self_ids:
        interactions.append(
            InteractionEvent(
                identifier=sender_id,
                direction="inbound",
                channel=channel,
                timestamp=timestamp,
                name=sender_name,
                org=sender_org,
                role=sender_role,
            )
        )
    elif direction == "outbound":
        for identifier, name, org, role in to_participants:
            if not identifier or identifier in self_ids:
                continue
            interactions.append(
                InteractionEvent(
                    identifier=identifier,
                    direction="outbound",
                    channel=channel,
                    timestamp=timestamp,
                    name=name,
                    org=org,
                    role=role,
                )
            )
    else:
        seen = set()
        for identifier, name, org, role in to_participants + [(sender_id, sender_name, sender_org, sender_role)]:
            if not identifier or identifier in self_ids or identifier in seen:
                continue
            seen.add(identifier)
            interactions.append(
                InteractionEvent(
                    identifier=identifier,
                    direction="unknown",
                    channel=channel,
                    timestamp=timestamp,
                    name=name,
                    org=org,
                    role=role,
                )
            )

    return interactions


def load_people_enrichment(path: str) -> Dict[str, Dict[str, str]]:
    mapping: Dict[str, Dict[str, str]] = {}
    with open(path, "r", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for row in reader:
            identifier = normalize_identifier(
                pick_first_non_empty(
                    [
                        row.get("identifier"),
                        row.get("email"),
                        row.get("phone"),
                        row.get("id"),
                    ]
                )
            )
            if not identifier:
                continue
            mapping[identifier] = {
                "name": pick_first_non_empty([row.get("name"), row.get("full_name")]),
                "org": pick_first_non_empty([row.get("org"), row.get("company"), row.get("organization")]),
                "role": pick_first_non_empty([row.get("role"), row.get("title")]),
            }
    return mapping


def compute_strength(stats: InteractionStats, now: datetime) -> float:
    volume_score = min(1.0, stats.total_weight / 20.0)

    directional_total = stats.inbound_weight + stats.outbound_weight
    if directional_total > 0.0:
        bidirectional_score = 2.0 * min(stats.inbound_weight, stats.outbound_weight) / directional_total
    else:
        bidirectional_score = 0.0

    if stats.latest_ts is None:
        recency_score = 0.0
    else:
        age_days = max(0.0, (now - stats.latest_ts).total_seconds() / 86400.0)
        recency_score = math.exp(-age_days / 45.0)

    diversity_score = min(1.0, len(stats.channels) / 4.0)

    strength = (
        0.40 * volume_score
        + 0.30 * bidirectional_score
        + 0.20 * recency_score
        + 0.10 * diversity_score
    )
    return max(0.0, min(1.0, strength))


def build_datasets(
    records: Iterable[Dict[str, Any]],
    self_identifiers: Sequence[str],
    channel_weights: Dict[str, float],
    min_strength: float,
    max_contacts: int,
    people_enrichment: Optional[Dict[str, Dict[str, str]]] = None,
) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]]]:
    self_ids = {normalize_identifier(value) for value in self_identifiers if normalize_identifier(value)}

    stats_by_identifier: Dict[str, InteractionStats] = {}

    for record in records:
        for interaction in event_to_interactions(record, self_ids):
            identifier = interaction.identifier
            if not identifier or identifier in self_ids:
                continue

            stat = stats_by_identifier.get(identifier)
            if stat is None:
                stat = InteractionStats(identifier=identifier)
                stats_by_identifier[identifier] = stat

            channel = interaction.channel or "unknown"
            weight = channel_weights.get(channel, channel_weights.get("unknown", 0.7))
            stat.total_weight += weight

            if interaction.direction == "inbound":
                stat.inbound_weight += weight
            elif interaction.direction == "outbound":
                stat.outbound_weight += weight

            stat.channels.add(channel)
            if interaction.timestamp is not None and (stat.latest_ts is None or interaction.timestamp > stat.latest_ts):
                stat.latest_ts = interaction.timestamp

            if interaction.name and not stat.name:
                stat.name = interaction.name
            if interaction.org and not stat.org:
                stat.org = interaction.org
            if interaction.role and not stat.role:
                stat.role = interaction.role

    now = datetime.now(timezone.utc)
    enriched = people_enrichment or {}

    rows: List[Tuple[float, InteractionStats]] = []
    for stat in stats_by_identifier.values():
        strength = compute_strength(stat, now)
        if strength < min_strength:
            continue
        rows.append((strength, stat))

    rows.sort(key=lambda item: item[0], reverse=True)
    rows = rows[:max_contacts]

    contacts: List[Dict[str, Any]] = []
    interactions: List[Dict[str, Any]] = []

    for strength, stat in rows:
        enrichment = enriched.get(stat.identifier, {})
        name = enrichment.get("name") or stat.name or stat.identifier
        org = enrichment.get("org") or stat.org
        role = enrichment.get("role") or stat.role

        contacts.append(
            {
                "name": name,
                "email": stat.identifier,
                "org": org,
                "role": role,
                "strength": round(strength, 3),
            }
        )
        interactions.append({"email": stat.identifier, "strength": round(strength, 3)})

    return contacts, interactions


def ingest_dataset(url: str, dataset: str, records: List[Dict[str, Any]], timeout: int) -> Dict[str, Any]:
    payload = {"dataset": dataset, "records": records}
    resp = requests.post(f"{url.rstrip('/')}/darkmesh/ingest", json=payload, timeout=timeout)
    resp.raise_for_status()
    return resp.json()


def is_connected_integration(item: Dict[str, Any]) -> bool:
    for key in ["connected", "is_connected", "enabled", "active", "ready"]:
        if key in item:
            try:
                return bool(item.get(key))
            except Exception:
                return False

    status = str(item.get("status", "")).strip().lower()
    if status:
        return status in {
            "connected",
            "active",
            "ready",
            "enabled",
            "ok",
            "healthy",
            "success",
        }

    return True


def item_to_source_ref(item: Dict[str, Any]) -> Optional[SourceRef]:
    source_id = pick_first_non_empty(
        [
            item.get("id"),
            item.get("integration_id"),
            item.get("source_id"),
            item.get("connector_id"),
            item.get("slug"),
            item.get("key"),
            item.get("name"),
            item.get("provider"),
            item.get("type"),
        ]
    )
    name = pick_first_non_empty(
        [
            item.get("name"),
            item.get("provider"),
            item.get("type"),
            item.get("integration"),
            item.get("connector"),
            item.get("slug"),
            source_id,
        ]
    )
    provider = pick_first_non_empty([item.get("provider"), item.get("type"), name])

    if not source_id and not name:
        return None

    if not source_id:
        source_id = name

    return SourceRef(source_id=str(source_id), name=str(name), provider=str(provider))


def source_matches_filters(source: SourceRef, include_filters: Set[str], exclude_filters: Set[str]) -> bool:
    haystack = " ".join(
        [
            normalize_name_token(source.source_id),
            normalize_name_token(source.name),
            normalize_name_token(source.provider),
        ]
    )

    if include_filters and not any(token in haystack for token in include_filters):
        return False
    if exclude_filters and any(token in haystack for token in exclude_filters):
        return False
    return True


def discover_sources(
    base_url: str,
    headers: Dict[str, str],
    timeout: int,
    integrations_path: str,
    status_path: str,
    include_filters: Set[str],
    exclude_filters: Set[str],
) -> List[SourceRef]:
    candidate_paths = [
        integrations_path,
        status_path,
        "/api/sources",
        "/api/connectors",
    ]

    items: List[Dict[str, Any]] = []
    seen_endpoints = set()
    for path in candidate_paths:
        url = combine_url(base_url, path)
        if url in seen_endpoints:
            continue
        seen_endpoints.add(url)
        try:
            resp = requests.get(url, headers=headers, timeout=timeout)
            resp.raise_for_status()
            payload = resp.json()
        except requests.RequestException:
            continue
        except ValueError:
            continue

        items.extend(extract_integration_items(payload))

    found: List[SourceRef] = []
    dedupe = set()
    for item in items:
        if not isinstance(item, dict):
            continue
        if not is_connected_integration(item):
            continue

        source = item_to_source_ref(item)
        if source is None:
            continue
        if not source_matches_filters(source, include_filters, exclude_filters):
            continue

        key = (normalize_name_token(source.source_id), normalize_name_token(source.provider))
        if key in dedupe:
            continue
        dedupe.add(key)
        found.append(source)

    return found


def fetch_events_via_autodiscovery(
    base_url: str,
    headers: Dict[str, str],
    timeout: int,
    events_path: str,
    sources: List[SourceRef],
) -> Tuple[List[Dict[str, Any]], Dict[str, Any]]:
    source_ids = [source.source_id for source in sources if source.source_id]
    source_names = [source.name for source in sources if source.name]
    source_providers = [source.provider for source in sources if source.provider]

    base_events_url = combine_url(base_url, events_path)
    aggregate_urls = [base_events_url]

    if source_names:
        aggregate_urls.append(with_query(base_events_url, {"sources": ",".join(source_names)}))
    if source_ids:
        aggregate_urls.append(with_query(base_events_url, {"integrations": ",".join(source_ids)}))
        aggregate_urls.append(with_query(base_events_url, {"integration_ids": ",".join(source_ids)}))
    if source_providers:
        aggregate_urls.append(with_query(base_events_url, {"providers": ",".join(source_providers)}))

    for url in aggregate_urls:
        try:
            records = load_records_from_url(url, headers=headers, timeout=timeout)
        except requests.RequestException:
            continue
        if records:
            return records, {"mode": "aggregate", "url": url}

    records: List[Dict[str, Any]] = []
    used_urls: List[str] = []

    for source in sources:
        per_source_urls = [
            combine_url(base_url, f"/api/integrations/{source.source_id}/events"),
            combine_url(base_url, f"/api/sources/{source.source_id}/events"),
            combine_url(base_url, f"/api/connectors/{source.source_id}/events"),
            with_query(base_events_url, {"integration_id": source.source_id}),
            with_query(base_events_url, {"source": source.source_id}),
            with_query(base_events_url, {"provider": source.provider}),
        ]

        for url in per_source_urls:
            try:
                chunk = load_records_from_url(url, headers=headers, timeout=timeout)
            except requests.RequestException:
                continue
            if chunk:
                records.extend(chunk)
                used_urls.append(url)
                break

    if records:
        return records, {"mode": "per_source", "urls": used_urls}

    raise SystemExit(
        "Autodiscovery found sources but could not fetch events. "
        "Pass --events-url explicitly or override --openclaw-events-path."
    )


def main() -> None:
    parser = argparse.ArgumentParser(
        description=(
            "Sync OpenClaw-ingested data into Darkmesh. Supports direct OpenClaw API URLs and/or local files "
            "(JSON, JSON array, or NDJSON)."
        )
    )
    parser.add_argument("--url", required=True, help="Darkmesh node URL, e.g. http://localhost:8001")
    parser.add_argument("--events-file", action="append", default=[], help="Path to OpenClaw events JSON/NDJSON")
    parser.add_argument("--events-url", action="append", default=[], help="OpenClaw API URL returning event records")
    parser.add_argument(
        "--events-header",
        action="append",
        default=[],
        help="Request header for --events-url in KEY=VALUE format; can be repeated",
    )

    parser.add_argument(
        "--autodiscover",
        action="store_true",
        help="Auto-discover connected OpenClaw integrations and ingest their events",
    )
    parser.add_argument(
        "--openclaw-base-url",
        default="http://localhost:3000",
        help="Base OpenClaw URL used for autodiscovery",
    )
    parser.add_argument(
        "--openclaw-events-path",
        default="/api/events",
        help="OpenClaw events path for autodiscovery mode",
    )
    parser.add_argument(
        "--openclaw-integrations-path",
        default="/api/integrations",
        help="OpenClaw integrations list path for autodiscovery mode",
    )
    parser.add_argument(
        "--openclaw-status-path",
        default="/api/integrations/status",
        help="OpenClaw integrations status path for autodiscovery mode",
    )
    parser.add_argument(
        "--openclaw-token",
        help="Bearer token for OpenClaw API (optional; falls back to env var)",
    )
    parser.add_argument(
        "--openclaw-token-env",
        default="OPENCLAW_TOKEN",
        help="Env var name to read OpenClaw API token from",
    )
    parser.add_argument(
        "--include-source",
        action="append",
        default=[],
        help="Only include matching integration/source tokens (e.g. gmail)",
    )
    parser.add_argument(
        "--exclude-source",
        action="append",
        default=[],
        help="Exclude matching integration/source tokens",
    )

    parser.add_argument(
        "--self-identifier",
        action="append",
        default=[],
        help="Your own identifiers (email/phone) to exclude from contacts; repeat for multiple",
    )
    parser.add_argument("--people-file", help="Optional CSV enrichment with identifier,name,org,role")
    parser.add_argument(
        "--channel-weight",
        action="append",
        default=[],
        help="Override channel weights in channel=value format (e.g. gmail=1.1)",
    )
    parser.add_argument("--min-strength", type=float, default=0.05, help="Drop contacts below this score")
    parser.add_argument("--max-contacts", type=int, default=5000, help="Maximum contacts to ingest")
    parser.add_argument("--timeout", type=int, default=20)
    parser.add_argument("--dry-run", action="store_true")
    args = parser.parse_args()

    if not args.events_file and not args.events_url and not args.autodiscover:
        raise SystemExit("Provide at least one --events-file, --events-url, or --autodiscover")

    headers = parse_headers(args.events_header)
    token = args.openclaw_token or os.environ.get(args.openclaw_token_env, "")
    if token and "Authorization" not in headers:
        headers["Authorization"] = f"Bearer {token}"

    channel_weights = parse_channel_weights(args.channel_weight)

    all_records: List[Dict[str, Any]] = []
    autodiscovery_meta: Dict[str, Any] = {}

    for path in args.events_file:
        records = load_records_from_file(path)
        all_records.extend(records)

    for events_url in args.events_url:
        records = load_records_from_url(events_url, headers=headers, timeout=args.timeout)
        all_records.extend(records)

    if args.autodiscover:
        include_filters = {normalize_name_token(value) for value in args.include_source if value.strip()}
        exclude_filters = {normalize_name_token(value) for value in args.exclude_source if value.strip()}

        sources = discover_sources(
            base_url=args.openclaw_base_url,
            headers=headers,
            timeout=args.timeout,
            integrations_path=args.openclaw_integrations_path,
            status_path=args.openclaw_status_path,
            include_filters=include_filters,
            exclude_filters=exclude_filters,
        )

        if not sources:
            message = (
                "Autodiscovery could not find any connected OpenClaw integrations. "
                "Check token/base URL, or pass --events-url directly."
            )
            if all_records:
                autodiscovery_meta = {"warning": message, "sources": [], "records": 0}
            else:
                raise SystemExit(message)
        else:
            try:
                discovered_records, fetch_meta = fetch_events_via_autodiscovery(
                    base_url=args.openclaw_base_url,
                    headers=headers,
                    timeout=args.timeout,
                    events_path=args.openclaw_events_path,
                    sources=sources,
                )
                all_records.extend(discovered_records)
                autodiscovery_meta = {
                    "sources": [
                        {"source_id": source.source_id, "name": source.name, "provider": source.provider}
                        for source in sources
                    ],
                    "fetch": fetch_meta,
                    "records": len(discovered_records),
                }
            except SystemExit as exc:
                if all_records:
                    autodiscovery_meta = {
                        "warning": str(exc),
                        "sources": [
                            {"source_id": source.source_id, "name": source.name, "provider": source.provider}
                            for source in sources
                        ],
                        "records": 0,
                    }
                else:
                    raise

    people_enrichment = load_people_enrichment(args.people_file) if args.people_file else None

    contacts, interactions = build_datasets(
        records=all_records,
        self_identifiers=args.self_identifier,
        channel_weights=channel_weights,
        min_strength=max(0.0, min(1.0, args.min_strength)),
        max_contacts=max(1, args.max_contacts),
        people_enrichment=people_enrichment,
    )

    summary = {
        "events_processed": len(all_records),
        "contacts_prepared": len(contacts),
        "interactions_prepared": len(interactions),
    }
    if autodiscovery_meta:
        summary["autodiscovered_sources"] = len(autodiscovery_meta.get("sources", []))
        summary["autodiscovery_records"] = autodiscovery_meta.get("records", 0)

    if args.dry_run:
        preview = {
            "summary": summary,
            "top_contacts": contacts[:5],
        }
        if autodiscovery_meta:
            preview["autodiscovery"] = autodiscovery_meta
        print(json.dumps(preview, indent=2))
        return

    contacts_result = ingest_dataset(args.url, "contacts", contacts, timeout=args.timeout)
    interactions_result = ingest_dataset(args.url, "interactions", interactions, timeout=args.timeout)

    output = {
        "summary": summary,
        "ingest": {
            "contacts": contacts_result,
            "interactions": interactions_result,
        },
    }
    if autodiscovery_meta:
        output["autodiscovery"] = autodiscovery_meta
    print(json.dumps(output, indent=2))


if __name__ == "__main__":
    main()
