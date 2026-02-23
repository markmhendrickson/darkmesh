import argparse
import json
import os
import time
from typing import Any, Dict

import requests


NODE_API_PREFIX = "/darkmesh"
RELAY_API_PREFIX = "/darkmesh/relay"


def load_config(path: str) -> Dict[str, Any]:
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def normalize_url(url: str) -> str:
    return url.rstrip("/")


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


def register_node(relay_url: str, config: Dict[str, Any]) -> None:
    payload = {
        "relay_key": config.get("relay_key", ""),
        "node_id": config["node_id"],
        "url": normalize_url(config.get("listen_url", f"http://localhost:{int(config.get('port', 8001))}")),
        "capabilities": config.get("capabilities", ["warm_intro_v1"]),
    }
    resp = requests.post(f"{relay_url}{RELAY_API_PREFIX}/nodes/register", json=payload, timeout=5)
    resp.raise_for_status()


def process_post(local_url: str, post: Dict[str, Any]) -> None:
    request_id = post.get("request_id")
    requester_url = normalize_url(str(post.get("requester_url", "")))
    response_token = str(post.get("response_token", ""))

    if not request_id or not requester_url or not response_token:
        return

    local_resp = requests.post(
        f"{local_url}{NODE_API_PREFIX}/skills/warm-intro/psi/respond",
        json={
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

    direct_resp = requests.post(
        f"{requester_url}{NODE_API_PREFIX}/skills/warm-intro/inbox/{request_id}",
        json={
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

    local_url = normalize_url(config.get("listen_url", f"http://localhost:{int(config.get('port', 8001))}"))
    cursor_file = args.cursor_file or os.path.join(config.get("vault_path", "data"), "darkmesh_listener.cursor")

    cursor = load_cursor(cursor_file)

    while True:
        try:
            register_node(relay_url, config)

            pull_payload = {
                "relay_key": config.get("relay_key", ""),
                "node_id": config["node_id"],
                "capabilities": config.get("capabilities", ["warm_intro_v1"]),
                "cursor": cursor,
                "limit": 20,
            }
            pull_resp = requests.post(f"{relay_url}{RELAY_API_PREFIX}/posts/pull", json=pull_payload, timeout=10)
            pull_resp.raise_for_status()
            payload = pull_resp.json()

            posts = payload.get("posts", [])
            for post in posts:
                try:
                    process_post(local_url, post)
                except requests.RequestException:
                    continue

            cursor = int(payload.get("cursor", cursor))
            save_cursor(cursor_file, cursor)
        except requests.RequestException:
            pass

        time.sleep(max(0.2, args.poll_interval))


if __name__ == "__main__":
    main()
