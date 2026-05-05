"""Thin HTTP client for the Neotoma REST API.

Used by the Darkmesh service layer in Phase 1 to replace the vault as the
live contacts substrate. Reads only — writes go through the AAuth-signed
path in :mod:`darkmesh.aauth_signer`.

Three auth modes are supported on the read path:

- ``bearer`` (legacy): sends ``Authorization: Bearer <token>``. Broad
  scope — Neotoma grants the token access to every entity type it holds.
  Recommended only for nodes that have not yet migrated to a Neotoma
  ``agent_grant``.
- ``aauth`` (preferred): signs each request with the Darkmesh node's
  AAuth key. Neotoma's admission layer (>= 0.9.0, "Stronger AAuth
  Admission" release) verifies the signature, looks up an active
  ``agent_grant`` whose ``match_*`` triple matches the request's
  identity, and authenticates the request as the grant's owning user
  with capabilities scoped to the grant. An unprovisioned node is
  *denied* (``aauth.admitted: false`` from ``GET /session``) rather
  than silently retaining the legacy default-allow behaviour. The
  ``NEOTOMA_AGENT_CAPABILITIES_*`` env-var registry that older versions
  of this client referred to has been removed from Neotoma; provision
  grants via :file:`scripts/neotoma_grants_provision.py` (REST) or
  Neotoma's ``neotoma agents grants import`` CLI.
- ``auto`` (default): uses ``aauth`` when the signer env vars are
  present, otherwise falls back to ``bearer``. Recommended fallback
  order for new deployments is ``auto`` → ``aauth`` once the grant has
  been provisioned, with ``bearer`` reserved for legacy nodes still
  being migrated.

Entity snapshots are returned as plain dicts. Mapping them onto Darkmesh's
contact shape is delegated to :func:`darkmesh.neotoma_client.entity_to_contact`
so the service layer stays oblivious to Neotoma's schema naming.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

import requests

from darkmesh.aauth_signer import (
    SignerConfig,
    SignerConfigError,
    load_signer_config_from_env,
    signed_get,
    signed_request,
)


AUTH_MODE_BEARER = "bearer"
AUTH_MODE_AAUTH = "aauth"
AUTH_MODE_AUTO = "auto"

_VALID_AUTH_MODES = frozenset({AUTH_MODE_BEARER, AUTH_MODE_AAUTH, AUTH_MODE_AUTO})


class NeotomaClientConfigError(RuntimeError):
    """Raised when the client is asked to use AAuth without a signer."""


@dataclass
class NeotomaClient:
    base_url: str
    token: str = ""
    timeout: int = 15
    entity_type: str = "contact"
    max_entities: int = 2000
    auth_mode: str = AUTH_MODE_BEARER
    signer_config: Optional[SignerConfig] = None
    _resolved_auth_mode: str = field(init=False, repr=False, default=AUTH_MODE_BEARER)

    def __post_init__(self) -> None:
        mode = (self.auth_mode or AUTH_MODE_BEARER).lower()
        if mode not in _VALID_AUTH_MODES:
            raise NeotomaClientConfigError(
                f"auth_mode must be one of {sorted(_VALID_AUTH_MODES)}; got {self.auth_mode!r}"
            )
        self.auth_mode = mode
        self._resolved_auth_mode = self._resolve_auth_mode()

    def _resolve_auth_mode(self) -> str:
        """Collapse ``auto`` into a concrete mode.

        ``auto`` prefers AAuth when signer credentials are reachable and
        falls back to bearer otherwise, so existing deployments keep
        working without requiring AAuth provisioning. Explicit ``bearer``
        and ``aauth`` are honoured as given.
        """
        if self.auth_mode == AUTH_MODE_AAUTH:
            if self.signer_config is None:
                try:
                    self.signer_config = load_signer_config_from_env()
                except SignerConfigError as exc:
                    raise NeotomaClientConfigError(
                        "auth_mode='aauth' requires DARKMESH_AAUTH_PRIVATE_JWK(_PATH) "
                        f"and DARKMESH_AAUTH_SUB: {exc}"
                    ) from exc
            return AUTH_MODE_AAUTH
        if self.auth_mode == AUTH_MODE_AUTO:
            if self.signer_config is not None:
                return AUTH_MODE_AAUTH
            try:
                self.signer_config = load_signer_config_from_env()
                return AUTH_MODE_AAUTH
            except SignerConfigError:
                return AUTH_MODE_BEARER
        return AUTH_MODE_BEARER

    @property
    def resolved_auth_mode(self) -> str:
        """Concrete auth mode in use (``bearer`` or ``aauth``)."""
        return self._resolved_auth_mode

    def _bearer_headers(self) -> Dict[str, str]:
        headers = {"content-type": "application/json"}
        if self.token:
            headers["authorization"] = f"Bearer {self.token}"
        return headers

    def _url(self, path: str) -> str:
        return f"{self.base_url.rstrip('/')}{path}"

    def _request(
        self,
        method: str,
        path: str,
        *,
        json_body: Optional[Any] = None,
        params: Optional[Dict[str, Any]] = None,
    ) -> requests.Response:
        """Single request abstraction used by both reads.

        Routes through ``requests`` for bearer auth and through
        :mod:`darkmesh.aauth_signer` for AAuth, so the call sites above
        never have to branch on auth mode.
        """
        url = self._url(path)
        if self._resolved_auth_mode == AUTH_MODE_AAUTH:
            if method.upper() == "GET":
                return signed_get(
                    url,
                    params=params,
                    config=self.signer_config,
                    timeout=self.timeout,
                )
            return signed_request(
                method,
                url,
                json_body=json_body,
                params=params,
                config=self.signer_config,
                timeout=self.timeout,
            )
        return requests.request(
            method,
            url,
            json=json_body,
            params=params,
            headers=self._bearer_headers(),
            timeout=self.timeout,
        )

    def query_entities(
        self,
        entity_type: Optional[str] = None,
        limit: Optional[int] = None,
    ) -> List[Dict[str, Any]]:
        wanted = entity_type or self.entity_type
        cap = limit if limit is not None else self.max_entities
        collected: List[Dict[str, Any]] = []
        page_size = max(1, min(500, cap))
        offset = 0
        while len(collected) < cap:
            payload = {
                "entity_type": wanted,
                "limit": min(page_size, cap - len(collected)),
                "offset": offset,
                "include_snapshots": True,
            }
            resp = self._request("POST", "/entities/query", json_body=payload)
            resp.raise_for_status()
            body = resp.json() or {}
            entities = body.get("entities") or body.get("results") or []
            if not entities:
                break
            collected.extend(entities)
            if len(entities) < payload["limit"]:
                break
            offset += len(entities)
        return collected[:cap]

    def get_relationships(self, entity_id: str) -> Dict[str, List[Dict[str, Any]]]:
        resp = self._request("GET", f"/entities/{entity_id}/relationships")
        resp.raise_for_status()
        body = resp.json() or {}
        return {
            "outgoing": body.get("outgoing") or [],
            "incoming": body.get("incoming") or [],
        }


def _first_string(*values: Any) -> str:
    for value in values:
        if value is None:
            continue
        token = str(value).strip()
        if token:
            return token
    return ""


def _flatten(entity: Dict[str, Any]) -> Dict[str, Any]:
    snapshot = entity.get("snapshot") if isinstance(entity.get("snapshot"), dict) else {}
    merged: Dict[str, Any] = {}
    merged.update(entity)
    merged.update(snapshot or {})
    return merged


def _parse_ts(value: Any) -> Optional[datetime]:
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


def entity_to_contact(entity: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    """Map a Neotoma entity snapshot onto the Darkmesh contact shape.

    Returns ``None`` when the snapshot has no identifier we can key against.
    Includes the live provenance fields (``observation_count``,
    ``relationship_count``, ``last_observation_at``) so callers that want to
    compute strength on the fly (see :func:`contact_live_strength`) have the
    raw inputs.
    """
    merged = _flatten(entity)
    entity_id = _first_string(
        merged.get("entity_id"),
        merged.get("id"),
        entity.get("entity_id"),
        entity.get("id"),
    )
    if not entity_id:
        return None

    email = _first_string(
        merged.get("email"),
        merged.get("primary_email"),
        merged.get("work_email"),
    ).lower()
    return {
        "name": _first_string(
            merged.get("canonical_name"),
            merged.get("name"),
            merged.get("full_name"),
            merged.get("display_name"),
        ),
        "email": email,
        "org": _first_string(
            merged.get("org"),
            merged.get("company"),
            merged.get("organization"),
            merged.get("current_company"),
            merged.get("employer"),
        ),
        "role": _first_string(
            merged.get("role"),
            merged.get("title"),
            merged.get("job_title"),
        ),
        "strength": _first_string(merged.get("strength")) or None,
        "neotoma_entity_id": entity_id,
        "observation_count": merged.get("observation_count") or 0,
        "relationship_count": merged.get("relationship_count") or 0,
        "last_observation_at": _parse_ts(
            merged.get("last_observation_at")
            or merged.get("updated_at")
            or merged.get("last_seen_at")
        ),
    }


def contact_live_strength(contact: Dict[str, Any], now: Optional[datetime] = None) -> float:
    """Compute strength from a contact dict produced by :func:`entity_to_contact`.

    Mirrors the Phase 0 connector formula so online and synced paths agree
    when the same contact is scored. Breaking it out here keeps the service
    layer from duplicating math.
    """
    import math

    stamp = now or datetime.now(timezone.utc)
    observations = contact.get("observation_count") or 0
    relationships = contact.get("relationship_count") or 0
    last_obs = contact.get("last_observation_at")
    if isinstance(last_obs, str):
        last_obs = _parse_ts(last_obs)

    volume = 1.0 - math.exp(-max(0.0, float(observations)) / 8.0)
    relationship_score = 1.0 - math.exp(-max(0.0, float(relationships)) / 6.0)
    if last_obs is None:
        recency = 0.0
    else:
        age_days = max(0.0, (stamp - last_obs).total_seconds() / 86400.0)
        recency = math.exp(-age_days / 45.0)

    return max(
        0.0,
        min(1.0, 0.45 * volume + 0.20 * relationship_score + 0.35 * recency),
    )
