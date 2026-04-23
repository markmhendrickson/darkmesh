import hashlib
import hmac
import json
import logging
import os
import threading
import time
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse

import requests
from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import JSONResponse

from darkmesh.aauth_signer import SignerConfig, SignerConfigError, load_signer_config_from_env, signed_post
from darkmesh.models import (
    IngestRequest,
    WarmIntroConsentRequest,
    WarmIntroConsentResponse,
    WarmIntroRequest,
    WarmIntroResponse,
)
from darkmesh.neotoma_client import NeotomaClient, contact_live_strength, entity_to_contact
from darkmesh.policy import PolicyError, match_target, validate_constraints, validate_template
from darkmesh.psi import PRIME, apply_secret, blind_items, decode_values, encode_values, generate_secret
from darkmesh.vault import EncryptedVault


logger = logging.getLogger(__name__)


NODE_API_PREFIX = "/darkmesh"
RELAY_API_PREFIX = "/darkmesh/relay"


def _normalize_url(url: str) -> str:
    return url.rstrip("/")


def _is_local_url(url: str) -> bool:
    try:
        host = (urlparse(url).hostname or "").lower()
    except ValueError:
        return False
    return host in {"localhost", "127.0.0.1", "::1"}


def _coerce_strength(value: Any, default: float = 0.5) -> float:
    try:
        return float(value)
    except (TypeError, ValueError):
        return default


def _extract_node_key(request: Request) -> str:
    direct = request.headers.get("x-darkmesh-key", "").strip()
    if direct:
        return direct

    auth = request.headers.get("authorization", "").strip()
    if auth.lower().startswith("bearer "):
        return auth[7:].strip()
    return ""


class DarkmeshConfig:
    def __init__(self, raw: Dict[str, Any]) -> None:
        self.node_id = raw["node_id"]
        self.vault_path = raw["vault_path"]
        self.self_identifiers = raw.get("self_identifiers", [])
        self.pseudonym_id = raw.get("pseudonym_id", self.node_id)
        self.capabilities = raw.get("capabilities", ["warm_intro_v1"])
        self.dev_mode = bool(raw.get("dev_mode", False))

        self.port = int(raw.get("port", os.environ.get("DARKMESH_PORT", "8001")))
        self.listen_url = _normalize_url(raw.get("listen_url", f"http://localhost:{self.port}"))

        self.relay_url = _normalize_url(raw.get("relay_url", "")) if raw.get("relay_url") else ""
        self.relay_key = raw.get("relay_key", "")
        if self.relay_url and not self.relay_key:
            raise ValueError("relay_key is required when relay_url is configured")

        self.node_key = raw.get("node_key", self.relay_key or os.environ.get("DARKMESH_NODE_KEY", ""))
        if not self.node_key:
            raise ValueError("node_key is required")

        self.response_wait_seconds = float(raw.get("response_wait_seconds", 5.0))
        self.post_ttl_seconds = int(raw.get("post_ttl_seconds", 30))
        self.required_integrations = raw.get("required_integrations", ["contacts", "interactions"])
        self.warm_intro_session_ttl = float(raw.get("warm_intro_session_ttl", 900.0))
        self.reveal_token_ttl_seconds = float(raw.get("reveal_token_ttl_seconds", 900.0))

        # Phase 1: optional Neotoma-backed vault. When `neotoma_url` is set,
        # contact lookups go through the live entity graph instead of the
        # encrypted flat-file vault. Absent config falls through to the
        # vault for backward compatibility.
        self.neotoma_url = _normalize_url(raw.get("neotoma_url", "")) if raw.get("neotoma_url") else ""
        self.neotoma_token = raw.get(
            "neotoma_token", os.environ.get("NEOTOMA_TOKEN", "")
        )
        self.neotoma_entity_type = raw.get("neotoma_entity_type", "contact")
        self.neotoma_max_entities = int(raw.get("neotoma_max_entities", 2000))
        self.neotoma_cache_ttl_seconds = float(raw.get("neotoma_cache_ttl_seconds", 15.0))


def load_config(path: str) -> DarkmeshConfig:
    with open(path, "r", encoding="utf-8") as f:
        raw = json.load(f)
    return DarkmeshConfig(raw)


class ContactStore:
    """Source of truth for contacts/interactions during warm-intro eval.

    Wraps the existing :class:`EncryptedVault`. When ``config.neotoma_url`` is
    configured, reads the contact list from Neotoma's live entity graph and
    derives the interactions dataset from each contact's provenance signals
    (observation count, relationship count, recency). A short TTL cache
    prevents one warm-intro request from hitting Neotoma three times.
    """

    def __init__(self, config: DarkmeshConfig, vault: EncryptedVault) -> None:
        self._config = config
        self._vault = vault
        self._client: Optional[NeotomaClient] = None
        if config.neotoma_url:
            self._client = NeotomaClient(
                base_url=config.neotoma_url,
                token=config.neotoma_token,
                entity_type=config.neotoma_entity_type,
                max_entities=config.neotoma_max_entities,
            )
        self._cache_lock = threading.Lock()
        self._cache: Dict[str, Any] = {"fetched_at": 0.0, "contacts": None, "interactions": None}

    @property
    def live(self) -> bool:
        return self._client is not None

    def _refresh_live_locked(self) -> None:
        assert self._client is not None
        entities = self._client.query_entities()
        contacts: List[Dict[str, Any]] = []
        interactions: List[Dict[str, Any]] = []
        for entity in entities:
            mapped = entity_to_contact(entity)
            if mapped is None:
                continue
            strength = contact_live_strength(mapped)
            contact_record = {
                "name": mapped.get("name") or mapped.get("email") or mapped.get("neotoma_entity_id"),
                "email": mapped.get("email") or "",
                "org": mapped.get("org") or "",
                "role": mapped.get("role") or "",
                "strength": round(strength, 3),
                "neotoma_entity_id": mapped.get("neotoma_entity_id"),
            }
            contacts.append(contact_record)
            if contact_record["email"]:
                interactions.append(
                    {"email": contact_record["email"], "strength": round(strength, 3)}
                )
        self._cache = {
            "fetched_at": time.time(),
            "contacts": contacts,
            "interactions": interactions,
        }

    def _live(self, dataset: str) -> List[Dict[str, Any]]:
        ttl = max(0.0, self._config.neotoma_cache_ttl_seconds)
        with self._cache_lock:
            fresh = (time.time() - float(self._cache.get("fetched_at", 0.0))) < ttl
            if not fresh or self._cache.get(dataset) is None:
                try:
                    self._refresh_live_locked()
                except requests.RequestException as exc:
                    logger.warning("Neotoma fetch failed, falling back to vault: %s", exc)
                    return list(self._vault.load(dataset))
            return list(self._cache.get(dataset) or [])

    def load(self, dataset: str) -> List[Dict[str, Any]]:
        if self.live and dataset in {"contacts", "interactions"}:
            return self._live(dataset)
        return self._vault.load(dataset)

    def append(self, dataset: str, records: List[Dict[str, Any]]) -> int:
        # Ingest always targets the local vault. Live Neotoma data is read-only
        # on this path; writebacks are handled via AAuth in Phase 2.
        return self._vault.append(dataset, records)


class NeotomaWriteback:
    """Phase 2: AAuth-signed writeback of Darkmesh events to Neotoma.

    A warm-intro reveal is a first-class event worth provenance. When the
    Darkmesh node has both ``neotoma_url`` and AAuth credentials configured
    (``DARKMESH_AAUTH_PRIVATE_JWK`` + ``DARKMESH_AAUTH_SUB``), we mint a
    ``warm_intro_reveal`` entity in Neotoma on every successful reveal. If
    AAuth isn't configured we no-op silently — the reveal itself always
    succeeds regardless. Writebacks are also best-effort: transport or
    verification failures are logged but never propagated to the caller.
    """

    def __init__(self, config: DarkmeshConfig) -> None:
        self._config = config
        self._signer_config: Optional[SignerConfig] = None
        self._enabled = False
        if not config.neotoma_url:
            return
        try:
            self._signer_config = load_signer_config_from_env()
            self._enabled = True
        except SignerConfigError as exc:
            logger.info(
                "Darkmesh AAuth writeback disabled (config missing): %s", exc
            )

    @property
    def enabled(self) -> bool:
        return self._enabled

    def _idempotency_key(self, request_id: str, consent_id: str, side: str) -> str:
        raw = f"{self._config.node_id}:{request_id}:{consent_id}:{side}"
        return "warm_intro_reveal-" + hashlib.sha256(raw.encode("utf-8")).hexdigest()[:32]

    def _build_entity(
        self,
        *,
        request_id: str,
        consent_id: Optional[str],
        requester_node_id: str,
        responder_node_id: str,
        template: str,
        target: Dict[str, Any],
        intro: Dict[str, Any],
        approved: bool,
        side: str,
    ) -> Dict[str, Any]:
        relationship_strength = intro.get("relationship_strength")
        target_contact = intro.get("target_contact") or {}
        # Warm-intro targets sometimes use ``company`` (end-user facing) and
        # sometimes ``org`` (vault schema) interchangeably; accept either and
        # normalise to ``target_org``.
        target_org = target.get("org") or target.get("company")
        raw = {
            "entity_type": "warm_intro_reveal",
            "canonical_name": (
                f"Warm intro {request_id} -> {target_contact.get('name') or 'unknown'}"
            ),
            "request_id": request_id,
            "consent_id": consent_id,
            "requester_node_id": requester_node_id,
            "responder_node_id": responder_node_id,
            "darkmesh_node_id": self._config.node_id,
            "side": side,
            "template": template,
            "approved": bool(approved),
            "relationship_strength": relationship_strength,
            "target_org": target_org,
            "target_role": target.get("role"),
            "target_contact_name": target_contact.get("name"),
            "target_contact_org": target_contact.get("org"),
            "target_contact_role": target_contact.get("role"),
            "revealed_at": datetime.now(timezone.utc).isoformat(),
            "data_source": f"darkmesh-node:{self._config.node_id}",
        }
        # Drop null-valued fields. Neotoma's reducer computes entity snapshots
        # by taking the latest non-null value per field; if a brand-new entity
        # has a field whose only observation is null, the default-schema path
        # crashes on ``observations[0].fields[field]`` (empty filtered list).
        # See src/reducers/observation_reducer.ts. Required identity keys
        # (entity_type, canonical_name) are never null.
        return {k: v for k, v in raw.items() if v is not None}

    def record_reveal(
        self,
        *,
        request_id: str,
        consent_id: Optional[str],
        requester_node_id: str,
        responder_node_id: str,
        template: str,
        target: Dict[str, Any],
        intro: Dict[str, Any],
        approved: bool,
        side: str,
    ) -> None:
        if not self._enabled or self._signer_config is None:
            return
        if not approved:
            return
        entity = self._build_entity(
            request_id=request_id,
            consent_id=consent_id,
            requester_node_id=requester_node_id,
            responder_node_id=responder_node_id,
            template=template,
            target=target or {},
            intro=intro or {},
            approved=approved,
            side=side,
        )
        payload = {
            "entities": [entity],
            "idempotency_key": self._idempotency_key(
                request_id, consent_id or "_", side
            ),
            "source_priority": 90,
        }
        try:
            response = signed_post(
                f"{self._config.neotoma_url}/store",
                payload,
                config=self._signer_config,
                timeout=10,
            )
        except Exception as exc:  # noqa: BLE001 -- best-effort writeback
            logger.warning("Neotoma writeback failed (%s): %s", side, exc)
            return
        if response.status_code >= 400:
            logger.warning(
                "Neotoma writeback rejected (%s, status=%s): %s",
                side,
                response.status_code,
                response.text[:500],
            )
        else:
            logger.info(
                "Neotoma writeback stored warm_intro_reveal (%s, request_id=%s)",
                side,
                request_id,
            )


def create_app() -> FastAPI:
    config_path = os.environ.get("DARKMESH_CONFIG", "config/node_a.json")
    config = load_config(config_path)
    vault = EncryptedVault(config.vault_path)
    store = ContactStore(config, vault)
    writeback = NeotomaWriteback(config)
    if writeback.enabled:
        logger.info(
            "Darkmesh AAuth writeback enabled -> %s (node=%s)",
            config.neotoma_url,
            config.node_id,
        )

    app = FastAPI(title=f"Darkmesh Node {config.node_id}")

    pending_lock = threading.Lock()
    pending_requests: Dict[str, Dict[str, Any]] = {}

    sessions_lock = threading.Lock()
    warm_intro_sessions: Dict[str, Dict[str, Any]] = {}

    reveal_tokens_lock = threading.Lock()
    issued_reveal_tokens: Dict[str, Dict[str, Any]] = {}

    public_paths = {f"{NODE_API_PREFIX}/health"}

    def cleanup_sessions_locked() -> None:
        now = time.time()
        stale_ids = []
        ttl = max(60.0, config.warm_intro_session_ttl)
        for request_id, record in warm_intro_sessions.items():
            created_at = float(record.get("created_at", 0.0))
            if now - created_at > ttl:
                stale_ids.append(request_id)
        for request_id in stale_ids:
            warm_intro_sessions.pop(request_id, None)

    def cleanup_reveal_tokens_locked() -> None:
        now = time.time()
        ttl = max(60.0, config.reveal_token_ttl_seconds)
        stale_tokens = []
        for token, record in issued_reveal_tokens.items():
            created_at = float(record.get("created_at", 0.0))
            if now - created_at > ttl:
                stale_tokens.append(token)
        for token in stale_tokens:
            issued_reveal_tokens.pop(token, None)

    def self_card() -> Dict[str, Any]:
        return {
            "node_id": config.node_id,
            "pseudonym_id": config.pseudonym_id,
            "url": config.listen_url,
            "capabilities": config.capabilities,
            "relay_url": config.relay_url,
        }

    def node_auth_headers() -> Dict[str, str]:
        return {"X-Darkmesh-Key": config.node_key}

    def publish_to_relay(payload: Dict[str, Any]) -> None:
        if not config.relay_url:
            raise HTTPException(status_code=500, detail="relay_url not configured")
        wire_payload = dict(payload)
        wire_payload["relay_key"] = config.relay_key
        try:
            relay_resp = requests.post(
                f"{config.relay_url}{RELAY_API_PREFIX}/posts",
                json=wire_payload,
                timeout=8,
            )
            relay_resp.raise_for_status()
        except requests.RequestException as exc:
            raise HTTPException(status_code=502, detail=f"Relay error: {exc}") from exc

    def dataset_count(dataset: str) -> int:
        return len(store.load(dataset))

    @app.middleware("http")
    async def auth_middleware(request: Request, call_next):  # type: ignore[override]
        path = request.url.path
        if not path.startswith(NODE_API_PREFIX) or path in public_paths:
            return await call_next(request)

        provided_key = _extract_node_key(request)
        if not provided_key or not hmac.compare_digest(provided_key, config.node_key):
            return JSONResponse(status_code=401, content={"detail": "invalid node key"})

        return await call_next(request)

    @app.on_event("startup")
    def register_node() -> None:
        if not config.relay_url:
            return
        payload = {
            "relay_key": config.relay_key,
            "node_id": config.node_id,
            "url": config.listen_url,
            "capabilities": config.capabilities,
        }
        try:
            requests.post(f"{config.relay_url}{RELAY_API_PREFIX}/nodes/register", json=payload, timeout=3)
        except requests.RequestException:
            pass

    @app.get(f"{NODE_API_PREFIX}/health")
    def health() -> Dict[str, str]:
        return {"status": "ok", "node_id": config.node_id}

    @app.get(f"{NODE_API_PREFIX}/capabilities")
    def capabilities() -> Dict[str, Any]:
        return {"node_id": config.node_id, "capabilities": config.capabilities}

    @app.get(f"{NODE_API_PREFIX}/node/card")
    def node_card() -> Dict[str, Any]:
        return self_card()

    @app.get(f"{NODE_API_PREFIX}/integrations/status")
    def integrations_status() -> Dict[str, Any]:
        datasets = []
        ready = True
        for dataset in config.required_integrations:
            count = dataset_count(dataset)
            dataset_ready = count > 0
            if not dataset_ready:
                ready = False
            datasets.append({"name": dataset, "records": count, "ready": dataset_ready})

        return {
            "node_id": config.node_id,
            "ready": ready,
            "required_integrations": datasets,
        }

    @app.post(f"{NODE_API_PREFIX}/ingest")
    def ingest(request: IngestRequest) -> Dict[str, Any]:
        count = store.append(request.dataset, request.records)
        return {"dataset": request.dataset, "count": count}

    @app.post(f"{NODE_API_PREFIX}/skills/warm-intro/request", response_model=WarmIntroResponse)
    def warm_intro_request(request: WarmIntroRequest) -> WarmIntroResponse:
        try:
            validate_template(request.template)
            constraints = validate_constraints(request.constraints.model_dump())
        except PolicyError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc

        contacts = vault.load("contacts")
        interactions = vault.load("interactions")

        if not contacts:
            raise HTTPException(status_code=400, detail="contacts integration has no records")

        interaction_map: Dict[str, float] = {}
        for record in interactions:
            email = (record.get("email") or "").strip().lower()
            if not email:
                continue
            interaction_map[email] = _coerce_strength(record.get("strength", 0.5))

        identifiers: List[str] = []
        strengths: List[float] = []
        for contact in contacts:
            email = contact.get("email")
            if not email:
                continue
            normalized = str(email).strip().lower()
            identifiers.append(normalized)
            strengths.append(_coerce_strength(interaction_map.get(normalized, contact.get("strength", 0.5))))

        if not identifiers:
            raise HTTPException(status_code=400, detail="No contacts available")

        if not config.relay_url:
            raise HTTPException(status_code=500, detail="relay_url not configured")

        secret_a = generate_secret(PRIME)
        blinded_x = blind_items(identifiers, secret_a, PRIME)

        request_id = uuid.uuid4().hex[:8]
        response_token = uuid.uuid4().hex

        with pending_lock:
            pending_requests[request_id] = {
                "token": response_token,
                "responses": [],
                "created_at": time.time(),
            }

        try:
            publish_to_relay(
                {
                    "request_id": request_id,
                    "requester_id": config.node_id,
                    "requester_url": config.listen_url,
                    "template": request.template,
                    "target": request.target.model_dump(),
                    "constraints": constraints,
                    "psi": {
                        "protocol": "dh-psi-v1",
                        "p": format(PRIME, "x"),
                        "x_values": encode_values(blinded_x),
                    },
                    "response_token": response_token,
                    "ttl_seconds": config.post_ttl_seconds,
                }
            )
        except HTTPException:
            with pending_lock:
                pending_requests.pop(request_id, None)
            raise

        deadline = time.time() + max(0.1, config.response_wait_seconds)
        while time.time() < deadline:
            time.sleep(0.1)

        with pending_lock:
            request_slot = pending_requests.pop(request_id, {"responses": []})
            responses = list(request_slot.get("responses", []))

        candidate_details: List[Dict[str, Any]] = []
        seen_pseudonyms = set()

        for response in responses:
            if not response.get("eligible"):
                continue

            psi_payload = response.get("psi") or {}
            x_values_b = decode_values(psi_payload.get("x_values_b", []))
            y_values_b = decode_values(psi_payload.get("y_values_b", []))
            if not x_values_b or not y_values_b:
                continue

            x_values_b_map: Dict[int, int] = {value: idx for idx, value in enumerate(x_values_b)}

            intersection_index = None
            for yb in y_values_b:
                yba = pow(yb, secret_a, PRIME)
                if yba in x_values_b_map:
                    intersection_index = x_values_b_map.get(yba)
                    break

            if intersection_index is None or intersection_index >= len(strengths):
                continue

            local_strength = strengths[intersection_index]
            target_strength = _coerce_strength(response.get("target_strength", 0.5))
            score = 0.6 * local_strength + 0.4 * target_strength
            if score < constraints["min_strength"]:
                continue

            responder = response.get("responder") or {}
            pseudonym_id = str(responder.get("pseudonym_id", "unknown"))
            responder_node_id = str(responder.get("node_id", ""))
            responder_url = _normalize_url(str(response.get("responder_url") or responder.get("url") or ""))
            reveal_token = str(response.get("reveal_token", "")).strip()

            if pseudonym_id in seen_pseudonyms:
                continue
            if not responder_url or not reveal_token:
                continue

            seen_pseudonyms.add(pseudonym_id)
            candidate_details.append(
                {
                    "pseudonym_id": pseudonym_id,
                    "score": round(score, 3),
                    "requires_consent": True,
                    "responder_node_id": responder_node_id,
                    "responder_url": responder_url,
                    "target_strength": round(target_strength, 3),
                    "local_strength": round(local_strength, 3),
                    "reveal_token": reveal_token,
                }
            )

        candidate_details.sort(key=lambda item: item["score"], reverse=True)
        candidate_details = candidate_details[: constraints["max_candidates"]]

        candidates: List[Dict[str, Any]] = []
        session_candidates: Dict[str, Dict[str, Any]] = {}
        for item in candidate_details:
            consent_id = uuid.uuid4().hex[:10]
            session_candidates[consent_id] = {
                "pseudonym_id": item["pseudonym_id"],
                "responder_node_id": item["responder_node_id"],
                "responder_url": item["responder_url"],
                "score": item["score"],
                "reveal_token": item["reveal_token"],
            }
            candidates.append(
                {
                    "pseudonym_id": item["pseudonym_id"],
                    "score": item["score"],
                    "requires_consent": True,
                    "consent_id": consent_id,
                }
            )

        if session_candidates:
            with sessions_lock:
                cleanup_sessions_locked()
                warm_intro_sessions[request_id] = {
                    "created_at": time.time(),
                    "template": request.template,
                    "target": request.target.model_dump(),
                    "candidates": session_candidates,
                }

        privacy_cost = round(0.1 * max(1, len(responses)), 3)
        return WarmIntroResponse(request_id=request_id, candidates=candidates, privacy_cost=privacy_cost)

    @app.post(f"{NODE_API_PREFIX}/skills/warm-intro/consent", response_model=WarmIntroConsentResponse)
    def warm_intro_consent(request: WarmIntroConsentRequest) -> WarmIntroConsentResponse:
        with sessions_lock:
            cleanup_sessions_locked()
            session = warm_intro_sessions.get(request.request_id)
            if session is None:
                raise HTTPException(status_code=404, detail="request_id not found or expired")

            candidate = (session.get("candidates") or {}).get(request.consent_id)
            if candidate is None:
                raise HTTPException(status_code=404, detail="consent_id not found")

            cached_result = candidate.get("reveal_result")
            target = session.get("target") or {}
            template = str(session.get("template", "warm_intro_v1"))

        pseudonym_id = str(candidate.get("pseudonym_id", "unknown"))

        if cached_result is not None:
            return WarmIntroConsentResponse(
                request_id=request.request_id,
                consent_id=request.consent_id,
                approved=bool(cached_result.get("approved", False)),
                pseudonym_id=pseudonym_id,
                intro=cached_result.get("intro"),
            )

        responder_url = _normalize_url(str(candidate.get("responder_url", "")))
        if not responder_url:
            raise HTTPException(status_code=502, detail="candidate responder url unavailable")

        reveal_payload = {
            "request_id": request.request_id,
            "requester_id": config.node_id,
            "template": template,
            "target": target,
            "candidate": {
                "pseudonym_id": pseudonym_id,
                "responder_node_id": candidate.get("responder_node_id"),
            },
            "reveal_token": candidate.get("reveal_token"),
        }

        try:
            reveal_resp = requests.post(
                f"{responder_url}{NODE_API_PREFIX}/skills/warm-intro/reveal",
                json=reveal_payload,
                headers=node_auth_headers(),
                timeout=8,
            )
            reveal_resp.raise_for_status()
            reveal_payload_resp = reveal_resp.json()
        except requests.RequestException as exc:
            raise HTTPException(status_code=502, detail=f"Reveal error: {exc}") from exc

        approved = bool(reveal_payload_resp.get("approved", False))
        result = {
            "approved": approved,
            "intro": reveal_payload_resp.get("intro") if approved else None,
        }

        with sessions_lock:
            live = warm_intro_sessions.get(request.request_id)
            if live:
                live_candidate = (live.get("candidates") or {}).get(request.consent_id)
                if live_candidate is not None:
                    live_candidate["reveal_result"] = result

        if approved and result.get("intro"):
            writeback.record_reveal(
                request_id=request.request_id,
                consent_id=request.consent_id,
                requester_node_id=config.node_id,
                responder_node_id=str(candidate.get("responder_node_id") or ""),
                template=template,
                target=target,
                intro=result.get("intro") or {},
                approved=True,
                side="requester",
            )

        return WarmIntroConsentResponse(
            request_id=request.request_id,
            consent_id=request.consent_id,
            approved=approved,
            pseudonym_id=pseudonym_id,
            intro=result.get("intro"),
        )

    @app.post(f"{NODE_API_PREFIX}/skills/warm-intro/inbox/{{request_id}}")
    def warm_intro_inbox(request_id: str, payload: Dict[str, Any]) -> Dict[str, Any]:
        response_token = str(payload.get("response_token", ""))
        response = payload.get("response") or payload

        with pending_lock:
            slot = pending_requests.get(request_id)
            if slot is None:
                raise HTTPException(status_code=404, detail="request not found")
            if slot.get("token") != response_token:
                raise HTTPException(status_code=403, detail="invalid response_token")
            slot["responses"].append(response)
            count = len(slot["responses"])

        return {"ok": True, "received": count}

    @app.post(f"{NODE_API_PREFIX}/skills/warm-intro/psi/respond")
    def warm_intro_psi_respond(payload: Dict[str, Any]) -> Dict[str, Any]:
        request_id = str(payload.get("request_id", "")).strip()
        requester_id = str(payload.get("requester_id", "")).strip()
        target = payload.get("target") or {}
        psi = payload.get("psi") or {}

        if not request_id or not requester_id:
            return {"request_id": request_id or None, "eligible": False}

        contacts = vault.load("contacts")
        interactions = vault.load("interactions")

        interaction_map: Dict[str, float] = {}
        for record in interactions:
            email = (record.get("email") or "").strip().lower()
            if not email:
                continue
            interaction_map[email] = _coerce_strength(record.get("strength", 0.5))

        matches = [c for c in contacts if match_target(c, target)]
        if not matches:
            return {"request_id": payload.get("request_id"), "eligible": False}

        target_strength = 0.5
        for contact in matches:
            email = (contact.get("email") or "").strip().lower()
            strength = interaction_map.get(email, _coerce_strength(contact.get("strength", 0.5)))
            target_strength = max(target_strength, _coerce_strength(strength))

        x_values = decode_values(psi.get("x_values", []))
        if not x_values:
            return {"request_id": payload.get("request_id"), "eligible": False}

        secret_b = generate_secret(PRIME)
        x_values_b = apply_secret(x_values, secret_b, PRIME)
        y_values_b = blind_items(config.self_identifiers, secret_b, PRIME)

        reveal_token = uuid.uuid4().hex
        with reveal_tokens_lock:
            cleanup_reveal_tokens_locked()
            issued_reveal_tokens[reveal_token] = {
                "created_at": time.time(),
                "request_id": request_id,
                "requester_id": requester_id,
            }

        return {
            "request_id": payload.get("request_id"),
            "eligible": True,
            "responder": {
                "node_id": config.node_id,
                "pseudonym_id": config.pseudonym_id,
                "url": config.listen_url,
            },
            "responder_url": config.listen_url,
            "target_strength": round(target_strength, 3),
            "reveal_token": reveal_token,
            "psi": {
                "protocol": "dh-psi-v1",
                "p": format(PRIME, "x"),
                "x_values_b": encode_values(x_values_b),
                "y_values_b": encode_values(y_values_b),
            },
        }

    @app.post(f"{NODE_API_PREFIX}/skills/warm-intro/reveal")
    def warm_intro_reveal(payload: Dict[str, Any]) -> Dict[str, Any]:
        request_id = str(payload.get("request_id", "")).strip()
        requester_id = str(payload.get("requester_id", "")).strip()
        template = str(payload.get("template", "warm_intro_v1")).strip()
        target = payload.get("target") or {}
        candidate = payload.get("candidate") or {}
        reveal_token = str(payload.get("reveal_token", "")).strip()

        if not requester_id:
            raise HTTPException(status_code=400, detail="requester_id is required")
        if not reveal_token:
            return {
                "request_id": request_id,
                "approved": False,
                "reason": "missing_reveal_token",
            }

        with reveal_tokens_lock:
            cleanup_reveal_tokens_locked()
            token_record = issued_reveal_tokens.get(reveal_token)
            if token_record is None:
                return {
                    "request_id": request_id,
                    "approved": False,
                    "reason": "invalid_reveal_token",
                }
            token_request_id = str(token_record.get("request_id", ""))
            token_requester_id = str(token_record.get("requester_id", ""))
            if token_request_id != request_id or token_requester_id != requester_id:
                return {
                    "request_id": request_id,
                    "approved": False,
                    "reason": "reveal_token_mismatch",
                }
            issued_reveal_tokens.pop(reveal_token, None)

        try:
            validate_template(template)
        except PolicyError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc

        expected_responder = str(candidate.get("responder_node_id", "")).strip()
        if expected_responder and expected_responder != config.node_id:
            return {
                "request_id": request_id,
                "approved": False,
                "reason": "candidate_mismatch",
            }

        contacts = vault.load("contacts")
        interactions = vault.load("interactions")

        interaction_map: Dict[str, float] = {}
        for record in interactions:
            email = (record.get("email") or "").strip().lower()
            if not email:
                continue
            interaction_map[email] = _coerce_strength(record.get("strength", 0.5))

        matches = [c for c in contacts if match_target(c, target)]
        if not matches:
            return {
                "request_id": request_id,
                "approved": False,
                "reason": "no_target_match",
            }

        best_contact: Dict[str, Any] = matches[0]
        best_strength = 0.0
        for contact in matches:
            email = (contact.get("email") or "").strip().lower()
            strength = interaction_map.get(email, _coerce_strength(contact.get("strength", 0.5)))
            strength = _coerce_strength(strength)
            if strength >= best_strength:
                best_strength = strength
                best_contact = contact

        intro = {
            "connector": {
                "node_id": config.node_id,
                "pseudonym_id": config.pseudonym_id,
            },
            "target_contact": {
                "name": best_contact.get("name"),
                "email": best_contact.get("email"),
                "org": best_contact.get("org"),
                "role": best_contact.get("role"),
            },
            "relationship_strength": round(best_strength, 3),
            "next_step": "Ask connector to forward an intro to the target contact.",
        }

        writeback.record_reveal(
            request_id=request_id,
            consent_id=None,
            requester_node_id=requester_id,
            responder_node_id=config.node_id,
            template=template,
            target=target,
            intro=intro,
            approved=True,
            side="responder",
        )

        return {
            "request_id": request_id,
            "approved": True,
            "intro": intro,
        }

    if config.dev_mode and _is_local_url(config.listen_url):

        @app.get(f"{NODE_API_PREFIX}/debug/dataset/{{name}}")
        def debug_dataset(name: str) -> Dict[str, Any]:
            return {"dataset": name, "records": vault.load(name)}

    return app


app = create_app()
