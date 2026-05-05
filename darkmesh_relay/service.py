"""Darkmesh relay FastAPI service.

Phase 3 adds AAuth (RFC 9421 + ``aa-agent+jwt``) as a parallel auth
mode alongside the original shared HMAC relay key. Three modes are
supported via :envvar:`DARKMESH_RELAY_AUTH_MODE`:

``hmac``
    Legacy: every request must embed ``relay_key`` in its JSON body (or
    ``X-Darkmesh-Key`` header on endpoints that don't take a body).
``aauth``
    Every request must carry an AAuth signature whose thumbprint is in
    the trust registry. ``relay_key`` in the body is ignored.
``either`` (default)
    Accept either of the above. Prefers AAuth when any of
    ``Signature``, ``Signature-Input``, or ``Signature-Key`` headers
    are present; otherwise falls back to HMAC. This is the migration
    mode: upstream Darkmesh clients keep working while new AAuth
    clients arrive.

Per-endpoint capability enforcement kicks in only on AAuth-authed
requests. The HMAC path continues to be "knowledge of the secret ==
full access", matching the pre-Phase-3 surface.
"""

from __future__ import annotations

import hmac
import json
import logging
import os
import time
import uuid
from dataclasses import dataclass
from typing import Any, Dict, List, Optional

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import JSONResponse

from darkmesh.aauth_verify import (
    AAuthVerifyError,
    VerifiedAgent,
    has_aauth_headers,
    verify_request,
)
from darkmesh.trust_registry import TrustRegistry, load_trust_registry_from_env


logger = logging.getLogger(__name__)


RELAY_API_PREFIX = "/darkmesh/relay"

# Capability strings for the relay surface. Node operators see these in
# their trust-registry entry alongside per-endpoint gates below.
CAPABILITY_REGISTER = "relay.register"
CAPABILITY_LIST = "relay.list"
CAPABILITY_PUBLISH = "relay.publish"
CAPABILITY_PULL = "relay.pull"


AUTH_MODES = ("hmac", "aauth", "either")


def _extract_header_key(request: Request) -> str:
    direct = request.headers.get("x-darkmesh-key", "").strip()
    if direct:
        return direct

    auth = request.headers.get("authorization", "").strip()
    if auth.lower().startswith("bearer "):
        return auth[7:].strip()
    return ""


@dataclass
class RelayAuthContext:
    """Authentication outcome stamped on a request by :class:`_AuthResolver`.

    ``agent`` is populated on AAuth-authed requests; ``hmac`` requests
    leave it ``None`` and rely on the knowledge-of-secret check having
    already succeeded upstream.
    """

    mode: str  # "hmac" | "aauth"
    agent: Optional[VerifiedAgent] = None


class DarkmeshRelayState:
    """In-memory relay state.

    HMAC enforcement remains on this object so endpoints that receive a
    JSON ``payload`` dict stay readable. AAuth enforcement is layered on
    top via the FastAPI middleware so state methods never need to know
    which auth mode a request arrived on.
    """

    def __init__(
        self,
        *,
        relay_key: str,
        auth_mode: str,
        trust_registry: TrustRegistry,
    ) -> None:
        auth_mode = (auth_mode or "either").lower()
        if auth_mode not in AUTH_MODES:
            raise ValueError(
                f"auth_mode must be one of {AUTH_MODES}, got {auth_mode!r}"
            )
        if auth_mode in {"hmac", "either"} and not relay_key:
            # `either` mode needs a relay key because HMAC-only clients
            # may still hit it; `aauth` mode doesn't need one.
            raise ValueError(
                "relay_key is required when auth_mode is 'hmac' or 'either'"
            )
        self.relay_key = relay_key
        self.auth_mode = auth_mode
        self.trust_registry = trust_registry
        self.nodes: Dict[str, Dict[str, Any]] = {}
        self.posts: List[Dict[str, Any]] = []
        self.seq = 0

    def _require_key_value(self, provided: str) -> None:
        if not provided or not hmac.compare_digest(provided, self.relay_key):
            raise HTTPException(status_code=403, detail="invalid relay_key")

    def _require_key(self, payload: Dict[str, Any]) -> None:
        provided = str(payload.get("relay_key", "")).strip()
        self._require_key_value(provided)

    def _cleanup_posts(self) -> None:
        now = time.time()
        self.posts = [post for post in self.posts if float(post.get("expires_at", now + 1)) > now]

    def register_node(
        self,
        payload: Dict[str, Any],
        *,
        auth: RelayAuthContext,
    ) -> Dict[str, Any]:
        if auth.mode == "hmac":
            self._require_key(payload)

        node_id = str(payload.get("node_id", "")).strip()
        url = str(payload.get("url", "")).strip().rstrip("/")
        capabilities = payload.get("capabilities", ["warm_intro_v1"])

        if not node_id or not url:
            raise HTTPException(status_code=400, detail="node_id and url are required")

        # When AAuth-authed, pin the registered node_id to the agent's
        # ``sub`` so a compromised key cannot squat another operator's
        # node_id. We enforce the suffix match rather than equality
        # because ``sub`` is ``darkmesh-node@<operator>`` and node_id
        # is ``<operator>``.
        if auth.mode == "aauth" and auth.agent is not None:
            agent_sub = auth.agent.sub
            if "@" in agent_sub:
                _, _, agent_scope = agent_sub.partition("@")
            else:
                agent_scope = agent_sub
            if agent_scope and agent_scope != node_id:
                raise HTTPException(
                    status_code=403,
                    detail=(
                        f"AAuth sub '{agent_sub}' does not match node_id "
                        f"'{node_id}'"
                    ),
                )

        record = {
            "node_id": node_id,
            "url": url,
            "capabilities": capabilities,
            "last_seen": time.time(),
        }
        self.nodes[node_id] = record
        return record

    def publish_post(
        self,
        payload: Dict[str, Any],
        *,
        auth: RelayAuthContext,
    ) -> Dict[str, Any]:
        if auth.mode == "hmac":
            self._require_key(payload)
        self._cleanup_posts()

        request_id = str(payload.get("request_id", "")).strip()
        requester_id = str(payload.get("requester_id", "")).strip()
        requester_url = str(payload.get("requester_url", "")).strip().rstrip("/")
        template = str(payload.get("template", "")).strip()
        target = payload.get("target") or {}
        psi = payload.get("psi") or {}
        constraints = payload.get("constraints") or {}
        response_token = str(payload.get("response_token", "")).strip()

        if not request_id or not requester_id or not requester_url or not template:
            raise HTTPException(
                status_code=400,
                detail="request_id, requester_id, requester_url, and template are required",
            )
        if not response_token:
            raise HTTPException(status_code=400, detail="response_token is required")

        ttl_seconds = int(payload.get("ttl_seconds", 30))
        ttl_seconds = max(5, min(300, ttl_seconds))

        self.seq += 1
        post = {
            "seq": self.seq,
            "post_id": uuid.uuid4().hex[:12],
            "request_id": request_id,
            "requester_id": requester_id,
            "requester_url": requester_url,
            "template": template,
            "target": target,
            "psi": psi,
            "constraints": constraints,
            "response_token": response_token,
            "created_at": time.time(),
            "expires_at": time.time() + ttl_seconds,
        }
        self.posts.append(post)
        return post

    def pull_posts(
        self,
        payload: Dict[str, Any],
        *,
        auth: RelayAuthContext,
    ) -> Dict[str, Any]:
        if auth.mode == "hmac":
            self._require_key(payload)
        self._cleanup_posts()

        node_id = str(payload.get("node_id", "")).strip()
        capabilities = payload.get("capabilities") or ["warm_intro_v1"]
        cursor = int(payload.get("cursor", 0))
        limit = int(payload.get("limit", 20))
        limit = max(1, min(100, limit))

        if not node_id:
            raise HTTPException(status_code=400, detail="node_id is required")

        allowed_templates = set(capabilities)
        candidates: List[Dict[str, Any]] = []
        max_seq = cursor

        for post in self.posts:
            seq = int(post.get("seq", 0))
            if seq <= cursor:
                continue
            max_seq = max(max_seq, seq)
            if post.get("requester_id") == node_id:
                continue
            if post.get("template") not in allowed_templates:
                continue
            candidates.append(post)
            if len(candidates) >= limit:
                break

        return {
            "node_id": node_id,
            "cursor": max_seq,
            "posts": candidates,
        }


def _resolve_auth_or_reject(
    state: DarkmeshRelayState,
    request: Request,
    body: bytes,
    *,
    required_capability: Optional[str],
) -> RelayAuthContext:
    """Shared auth resolution shared across the public POST endpoints.

    Returns a :class:`RelayAuthContext` or raises ``HTTPException`` with
    a 401/403. Capability enforcement only applies to AAuth mode — HMAC
    already gates access on secret knowledge, and layering capabilities
    on top would break the upstream shared-key semantics until
    operators migrate.
    """
    signature_present = has_aauth_headers(request.headers)
    if state.auth_mode == "aauth":
        if not signature_present:
            raise HTTPException(status_code=401, detail="AAuth signature required")
    elif state.auth_mode == "hmac":
        return RelayAuthContext(mode="hmac")
    # "either" mode or "aauth" mode with headers present:
    if not signature_present:
        return RelayAuthContext(mode="hmac")

    url = str(request.url)
    try:
        agent = verify_request(
            method=request.method,
            url=url,
            headers={k: v for k, v in request.headers.items()},
            body=body,
            trust_registry=state.trust_registry,
        )
    except AAuthVerifyError as exc:
        logger.warning(
            "AAuth verification failed on %s: %s (%s)",
            request.url.path,
            exc.reason,
            exc,
        )
        raise HTTPException(
            status_code=401,
            detail=f"AAuth verification failed: {exc.reason}",
        ) from exc
    if required_capability and not agent.has_capability(required_capability):
        logger.warning(
            "AAuth agent %s missing capability %s for %s",
            agent.sub,
            required_capability,
            request.url.path,
        )
        raise HTTPException(
            status_code=403,
            detail=(
                f"agent '{agent.sub}' is not permitted to use "
                f"capability '{required_capability}'"
            ),
        )
    return RelayAuthContext(mode="aauth", agent=agent)


async def _read_json_body(request: Request) -> Dict[str, Any]:
    raw = await request.body()
    if not raw:
        return {}
    try:
        parsed = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise HTTPException(status_code=400, detail=f"invalid JSON body: {exc}") from exc
    if not isinstance(parsed, dict):
        raise HTTPException(status_code=400, detail="request body must be a JSON object")
    return parsed


def create_app() -> FastAPI:
    relay_key = os.environ.get("DARKMESH_RELAY_KEY", "")
    auth_mode = (os.environ.get("DARKMESH_RELAY_AUTH_MODE", "either") or "either").lower()
    trust_registry = load_trust_registry_from_env(
        "DARKMESH_RELAY_TRUSTED_AGENTS_FILE",
        allow_missing=True,
    )
    # Fallback to the generic env var so operators with a single trust
    # file do not need to set two copies.
    if len(trust_registry) == 0:
        trust_registry = load_trust_registry_from_env(
            "DARKMESH_TRUSTED_AGENTS_FILE",
            allow_missing=True,
        )

    state = DarkmeshRelayState(
        relay_key=relay_key,
        auth_mode=auth_mode,
        trust_registry=trust_registry,
    )
    logger.info(
        "Darkmesh relay auth_mode=%s trust_registry_entries=%d",
        state.auth_mode,
        len(trust_registry),
    )

    app = FastAPI(title="Darkmesh Relay")

    @app.get(f"{RELAY_API_PREFIX}/health")
    def health() -> Dict[str, Any]:
        state._cleanup_posts()
        return {
            "status": "ok",
            "auth_mode": state.auth_mode,
            "nodes": len(state.nodes),
            "posts": len(state.posts),
        }

    @app.post(f"{RELAY_API_PREFIX}/nodes/register")
    async def nodes_register(request: Request) -> Dict[str, Any]:
        body = await request.body()
        auth = _resolve_auth_or_reject(
            state, request, body, required_capability=CAPABILITY_REGISTER
        )
        payload = await _read_json_body(request)
        record = state.register_node(payload, auth=auth)
        return {"ok": True, "node": record}

    @app.get(f"{RELAY_API_PREFIX}/nodes")
    async def nodes(request: Request) -> Dict[str, Any]:
        # GET has no body; AAuth mode still verifies over an empty body.
        if has_aauth_headers(request.headers) or state.auth_mode == "aauth":
            auth = _resolve_auth_or_reject(
                state, request, b"", required_capability=CAPABILITY_LIST
            )
            if auth.mode == "hmac":
                # auth_mode must have been 'aauth' to reach here without
                # signature headers; _resolve_auth_or_reject would have
                # 401ed. Defensive fallback.
                provided = _extract_header_key(request)
                state._require_key_value(provided)
        else:
            provided = _extract_header_key(request)
            state._require_key_value(provided)
        return {"nodes": list(state.nodes.values())}

    @app.post(f"{RELAY_API_PREFIX}/posts")
    async def posts_publish(request: Request) -> Dict[str, Any]:
        body = await request.body()
        auth = _resolve_auth_or_reject(
            state, request, body, required_capability=CAPABILITY_PUBLISH
        )
        payload = await _read_json_body(request)
        post = state.publish_post(payload, auth=auth)
        return {
            "ok": True,
            "post_id": post["post_id"],
            "seq": post["seq"],
            "expires_at": post["expires_at"],
        }

    @app.post(f"{RELAY_API_PREFIX}/posts/pull")
    async def posts_pull(request: Request) -> Dict[str, Any]:
        body = await request.body()
        auth = _resolve_auth_or_reject(
            state, request, body, required_capability=CAPABILITY_PULL
        )
        payload = await _read_json_body(request)
        return state.pull_posts(payload, auth=auth)

    @app.exception_handler(HTTPException)
    async def _http_exc_handler(_request: Request, exc: HTTPException) -> JSONResponse:
        return JSONResponse(status_code=exc.status_code, content={"detail": exc.detail})

    return app


app = create_app()
