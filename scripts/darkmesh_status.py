import argparse
import json
import os
from typing import Dict, List, Optional

import requests


NODE_API_PREFIX = "/darkmesh"
RELAY_API_PREFIX = "/darkmesh/relay"
RUNTIME_DIR = ".darkmesh"


def read_pid(path: str) -> Optional[int]:
    try:
        with open(path, "r", encoding="utf-8") as f:
            return int(f.read().strip())
    except (OSError, ValueError):
        return None


def list_pid_files() -> List[str]:
    if not os.path.isdir(RUNTIME_DIR):
        return []
    return [os.path.join(RUNTIME_DIR, name) for name in os.listdir(RUNTIME_DIR) if name.endswith(".pid")]


def load_config(path: str) -> Dict:
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def check_health(url: str) -> str:
    try:
        resp = requests.get(url, timeout=2)
        if resp.status_code == 200:
            return "ok"
        return f"error:{resp.status_code}"
    except requests.RequestException:
        return "down"


def node_headers(node_key: str) -> Dict[str, str]:
    token = node_key.strip()
    if not token:
        return {}
    return {"X-Darkmesh-Key": token}


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--config")
    parser.add_argument("--relay-url")
    parser.add_argument("--node-key", default=os.environ.get("DARKMESH_NODE_KEY", ""))
    args = parser.parse_args()

    pid_files = sorted(list_pid_files())
    if pid_files:
        print("PIDs:")
        for path in pid_files:
            pid = read_pid(path)
            name = os.path.basename(path).replace(".pid", "")
            print(f"- {name}: {pid}")
    else:
        print("No PID files found.")

    print("Health:")

    relay_url = args.relay_url
    node_key = args.node_key

    if args.config and os.path.exists(args.config):
        config = load_config(args.config)
        port = int(config.get("port", 8001))
        darkmesh_url = f"http://localhost:{port}"
        print(f"- darkmesh({config.get('node_id', 'node')}): {check_health(darkmesh_url + NODE_API_PREFIX + '/health')}")

        if not relay_url:
            relay_url = config.get("relay_url")

        if not node_key:
            node_key = str(config.get("node_key") or config.get("relay_key") or "")

        integration_url = darkmesh_url + NODE_API_PREFIX + "/integrations/status"
        try:
            integration_resp = requests.get(
                integration_url,
                headers=node_headers(node_key),
                timeout=2,
            )
            integration_resp.raise_for_status()
            status_payload = integration_resp.json()
            print(f"- integrations_ready: {status_payload.get('ready', False)}")
        except requests.RequestException:
            print("- integrations_ready: unknown")

    if relay_url:
        relay_url = relay_url.rstrip("/")
        print(f"- relay({relay_url}): {check_health(relay_url + RELAY_API_PREFIX + '/health')}")


if __name__ == "__main__":
    main()
