import json
import os
import threading
import time
import uuid
from typing import Any, Dict, List

import requests
from fastapi import FastAPI, HTTPException

from darkmesh.models import (
    IngestRequest,
    WarmIntroConsentRequest,
    WarmIntroConsentResponse,
    WarmIntroRequest,
    WarmIntroResponse,
)
from darkmesh.policy import PolicyError, match_target, validate_constraints, validate_template
from darkmesh.psi import PRIME, apply_secret, blind_items, decode_values, encode_values, generate_secret
from darkmesh.vault import EncryptedVault


NODE_API_PREFIX = "/darkmesh"
RELAY_API_PREFIX = "/darkmesh/relay"


def _normalize_url(url: str) -> str:
    return url.rstrip("/")


def _coerce_strength(value: Any, default: float = 0.5) -> float:
    try:
        return float(value)
    except (TypeError, ValueError):
        return default


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

        self.response_wait_seconds = float(raw.get("response_wait_seconds", 5.0))
        self.post_ttl_seconds = int(raw.get("post_ttl_seconds", 30))
        self.required_integrations = raw.get("required_integrations", ["contacts", "interactions"])
        self.warm_intro_session_ttl = float(raw.get("warm_intro_session_ttl", 900.0))


def load_config(path: str) -> DarkmeshConfig:
    with open(path, "r", encoding="utf-8") as f:
        raw = json.load(f)
    return DarkmeshConfig(raw)


def create_app() -> FastAPI:
    config_path = os.environ.get("DARKMESH_CONFIG", "config/node_a.json")
    config = load_config(config_path)
    vault = EncryptedVault(config.vault_path)

    app = FastAPI(title=f"Darkmesh Node {config.node_id}")

    pending_lock = threading.Lock()
    pending_requests: Dict[str, Dict[str, Any]] = {}

    sessions_lock = threading.Lock()
    warm_intro_sessions: Dict[str, Dict[str, Any]] = {}

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

    def self_card() -> Dict[str, Any]:
        return {
            "node_id": config.node_id,
            "pseudonym_id": config.pseudonym_id,
            "url": config.listen_url,
            "capabilities": config.capabilities,
            "relay_url": config.relay_url,
        }

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
        return len(vault.load(dataset))

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
        count = vault.append(request.dataset, request.records)
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

            if pseudonym_id in seen_pseudonyms:
                continue
            if not responder_url:
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
        }

        try:
            reveal_resp = requests.post(
                f"{responder_url}{NODE_API_PREFIX}/skills/warm-intro/reveal",
                json=reveal_payload,
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
        target = payload.get("target") or {}
        psi = payload.get("psi") or {}

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
            "psi": {
                "protocol": "dh-psi-v1",
                "p": format(PRIME, "x"),
                "x_values_b": encode_values(x_values_b),
                "y_values_b": encode_values(y_values_b),
            },
        }

    @app.post(f"{NODE_API_PREFIX}/skills/warm-intro/reveal")
    def warm_intro_reveal(payload: Dict[str, Any]) -> Dict[str, Any]:
        request_id = str(payload.get("request_id", ""))
        requester_id = str(payload.get("requester_id", "")).strip()
        template = str(payload.get("template", "warm_intro_v1")).strip()
        target = payload.get("target") or {}
        candidate = payload.get("candidate") or {}

        if not requester_id:
            raise HTTPException(status_code=400, detail="requester_id is required")

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

        return {
            "request_id": request_id,
            "approved": True,
            "intro": intro,
        }

    if config.dev_mode:

        @app.get(f"{NODE_API_PREFIX}/debug/dataset/{{name}}")
        def debug_dataset(name: str) -> Dict[str, Any]:
            return {"dataset": name, "records": vault.load(name)}

    return app


app = create_app()
