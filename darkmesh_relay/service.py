import hmac
import os
import time
import uuid
from typing import Any, Dict, List

from fastapi import FastAPI, HTTPException, Request


RELAY_API_PREFIX = "/darkmesh/relay"


def _extract_header_key(request: Request) -> str:
    direct = request.headers.get("x-darkmesh-key", "").strip()
    if direct:
        return direct

    auth = request.headers.get("authorization", "").strip()
    if auth.lower().startswith("bearer "):
        return auth[7:].strip()
    return ""


class DarkmeshRelayState:
    def __init__(self, relay_key: str) -> None:
        if not relay_key:
            raise ValueError("relay_key is required")

        self.relay_key = relay_key
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

    def register_node(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        self._require_key(payload)

        node_id = str(payload.get("node_id", "")).strip()
        url = str(payload.get("url", "")).strip().rstrip("/")
        capabilities = payload.get("capabilities", ["warm_intro_v1"])

        if not node_id or not url:
            raise HTTPException(status_code=400, detail="node_id and url are required")

        record = {
            "node_id": node_id,
            "url": url,
            "capabilities": capabilities,
            "last_seen": time.time(),
        }
        self.nodes[node_id] = record
        return record

    def publish_post(self, payload: Dict[str, Any]) -> Dict[str, Any]:
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

    def pull_posts(self, payload: Dict[str, Any]) -> Dict[str, Any]:
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


def create_app() -> FastAPI:
    relay_key = os.environ.get("DARKMESH_RELAY_KEY", "")
    state = DarkmeshRelayState(relay_key=relay_key)

    app = FastAPI(title="Darkmesh Relay")

    @app.get(f"{RELAY_API_PREFIX}/health")
    def health() -> Dict[str, Any]:
        state._cleanup_posts()
        return {
            "status": "ok",
            "nodes": len(state.nodes),
            "posts": len(state.posts),
        }

    @app.post(f"{RELAY_API_PREFIX}/nodes/register")
    def nodes_register(payload: Dict[str, Any]) -> Dict[str, Any]:
        record = state.register_node(payload)
        return {"ok": True, "node": record}

    @app.get(f"{RELAY_API_PREFIX}/nodes")
    def nodes(request: Request) -> Dict[str, Any]:
        provided = _extract_header_key(request)
        state._require_key_value(provided)
        return {"nodes": list(state.nodes.values())}

    @app.post(f"{RELAY_API_PREFIX}/posts")
    def posts_publish(payload: Dict[str, Any]) -> Dict[str, Any]:
        post = state.publish_post(payload)
        return {
            "ok": True,
            "post_id": post["post_id"],
            "seq": post["seq"],
            "expires_at": post["expires_at"],
        }

    @app.post(f"{RELAY_API_PREFIX}/posts/pull")
    def posts_pull(payload: Dict[str, Any]) -> Dict[str, Any]:
        return state.pull_posts(payload)

    return app


app = create_app()
