"""Darkmesh listener: polls the relay for pending warm-intro posts and
routes them through the local node.

Phase 3 extends the listener to sign its own relay + local + peer
callbacks with AAuth when configured. Behaviour by ``auth_mode``:

- ``hmac`` (or unset): retains the pre-Phase-3 behaviour — embeds
  ``relay_key`` in the body and sets ``X-Darkmesh-Key`` on inter-node
  hops.
- ``aauth`` / ``either``: uses :func:`signed_post` for every
  Darkmesh-internal call. Requires ``DARKMESH_AAUTH_PRIVATE_JWK(_PATH)``
  and ``DARKMESH_AAUTH_SUB`` to be set (see ``scripts/aauth_env.sh``).
  In ``either`` mode, HMAC credentials are still populated in the body
  / header as a fallback so an ``auth_mode=either`` peer accepts the
  hop even when it has not yet loaded our public JWK.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import time
from pathlib import Path
from typing import Any, Callable, Dict, Optional

import requests


REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))


from darkmesh.aauth_signer import (  # noqa: E402
    SignerConfig,
    SignerConfigError,
    load_signer_config_from_env,
    signed_post,
)


NODE_API_PREFIX = "/darkmesh"
RELAY_API_PREFIX = "/darkmesh/relay"


def load_config(path: str) -> Dict[str, Any]:
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def normalize_url(url: str) -> str:
    return url.rstrip("/")


def node_headers(config: Dict[str, Any]) -> Dict[str, str]:
    token = str(config.get("node_key") or config.get("relay_key") or os.environ.get("DARKMESH_NODE_KEY", "")).strip()
    if not token:
        # OK to be missing when the listener is running in AAuth-only
        # mode; we fall back to an empty header and rely on the signer.
        return {}
    return {"X-Darkmesh-Key": token}


def _resolve_auth_mode(config: Dict[str, Any]) -> str:
    mode = str(
        config.get("auth_mode") or os.environ.get("DARKMESH_AUTH_MODE", "either")
    ).lower()
    if mode not in {"hmac", "aauth", "either"}:
        raise SystemExit(
            f"auth_mode must be 'hmac', 'aauth', or 'either'; got {mode!r}"
        )
    return mode


def _resolve_signer_config(auth_mode: str) -> Optional[SignerConfig]:
    if auth_mode == "hmac":
        return None
    try:
        return load_signer_config_from_env()
    except SignerConfigError as exc:
        if auth_mode == "aauth":
            raise SystemExit(
                "auth_mode='aauth' requires DARKMESH_AAUTH_PRIVATE_JWK(_PATH) "
                f"and DARKMESH_AAUTH_SUB: {exc}"
            )
        return None


def _build_post(
    auth_mode: str,
    signer_config: Optional[SignerConfig],
    headers: Dict[str, str],
) -> Callable[..., requests.Response]:
    """Return a ``post(url, payload, *, timeout)`` closure honouring the
    requested auth mode.

    The closure keeps auth concerns out of :func:`process_post` and the
    main polling loop so the rest of the listener reads like the
    Phase-2 version.
    """

    def _post(url: str, payload: Dict[str, Any], *, timeout: int = 8) -> requests.Response:
        if auth_mode != "hmac" and signer_config is not None:
            return signed_post(url, payload, config=signer_config, timeout=timeout)
        return requests.post(url, json=payload, headers=headers, timeout=timeout)

    return _post


def load_cursor(path: str) -> int:
    if not os.path.exists(path):
        return 0
    try:
        with open(path, "r", encoding="utf-8") as f:
            return int(f.read().strip())
    except (OSError, ValueError):
        return 0


def save_cursor(path: str, cursor: int) -> None:
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        f.write(str(cursor))


def register_node(
    relay_url: str,
    config: Dict[str, Any],
    post: Callable[..., requests.Response],
) -> None:
    payload: Dict[str, Any] = {
        "node_id": config["node_id"],
        "url": normalize_url(config.get("listen_url", f"http://localhost:{int(config.get('port', 8001))}")),
        "capabilities": config.get("capabilities", ["warm_intro_v1"]),
    }
    if config.get("relay_key"):
        payload["relay_key"] = config["relay_key"]
    resp = post(f"{relay_url}{RELAY_API_PREFIX}/nodes/register", payload, timeout=5)
    resp.raise_for_status()


def process_post(
    local_url: str,
    post: Dict[str, Any],
    post_fn: Callable[..., requests.Response],
) -> None:
    request_id = post.get("request_id")
    requester_url = normalize_url(str(post.get("requester_url", "")))
    response_token = str(post.get("response_token", ""))

    if not request_id or not requester_url or not response_token:
        return

    local_resp = post_fn(
        f"{local_url}{NODE_API_PREFIX}/skills/warm-intro/psi/respond",
        {
            "request_id": request_id,
            "requester_id": post.get("requester_id"),
            "target": post.get("target"),
            "psi": post.get("psi"),
        },
        timeout=8,
    )
    local_resp.raise_for_status()

    response_payload = local_resp.json()
    if not response_payload.get("eligible"):
        return

    direct_resp = post_fn(
        f"{requester_url}{NODE_API_PREFIX}/skills/warm-intro/inbox/{request_id}",
        {
            "response_token": response_token,
            "response": response_payload,
        },
        timeout=8,
    )
    direct_resp.raise_for_status()


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--config", required=True)
    parser.add_argument("--poll-interval", type=float, default=1.0)
    parser.add_argument("--cursor-file")
    args = parser.parse_args()

    config = load_config(args.config)
    relay_url = normalize_url(str(config.get("relay_url", "")))
    if not relay_url:
        raise SystemExit("relay_url missing in config")

    auth_mode = _resolve_auth_mode(config)
    signer_config = _resolve_signer_config(auth_mode)
    headers = node_headers(config)
    if auth_mode == "hmac" and not headers:
        raise SystemExit("node_key missing in config")
    post_fn = _build_post(auth_mode, signer_config, headers)

    local_url = normalize_url(config.get("listen_url", f"http://localhost:{int(config.get('port', 8001))}"))
    cursor_file = args.cursor_file or os.path.join(config.get("vault_path", "data"), "darkmesh_listener.cursor")

    cursor = load_cursor(cursor_file)

    while True:
        try:
            register_node(relay_url, config, post_fn)

            pull_payload: Dict[str, Any] = {
                "node_id": config["node_id"],
                "capabilities": config.get("capabilities", ["warm_intro_v1"]),
                "cursor": cursor,
                "limit": 20,
            }
            if config.get("relay_key"):
                pull_payload["relay_key"] = config["relay_key"]
            pull_resp = post_fn(
                f"{relay_url}{RELAY_API_PREFIX}/posts/pull",
                pull_payload,
                timeout=10,
            )
            pull_resp.raise_for_status()
            payload = pull_resp.json()

            posts = payload.get("posts", [])
            for post_item in posts:
                try:
                    process_post(local_url, post_item, post_fn)
                except requests.RequestException:
                    continue

            cursor = int(payload.get("cursor", cursor))
            save_cursor(cursor_file, cursor)
        except requests.RequestException:
            pass

        time.sleep(max(0.2, args.poll_interval))


if __name__ == "__main__":
    main()
