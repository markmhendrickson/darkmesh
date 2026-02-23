import argparse
import json
import os
import sys

import requests


NODE_API_PREFIX = "/darkmesh"


def node_headers(node_key: str) -> dict:
    token = node_key.strip()
    if not token:
        raise SystemExit("node key is required (pass --node-key or set DARKMESH_NODE_KEY)")
    return {"X-Darkmesh-Key": token}


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--url", required=True, help="Darkmesh node URL, e.g. http://localhost:8001")
    parser.add_argument("--strict", action="store_true", help="Exit non-zero when integrations are not ready")
    parser.add_argument("--node-key", default=os.environ.get("DARKMESH_NODE_KEY", ""))
    args = parser.parse_args()

    base_url = args.url.rstrip("/")
    resp = requests.get(
        f"{base_url}{NODE_API_PREFIX}/integrations/status",
        headers=node_headers(args.node_key),
        timeout=8,
    )
    resp.raise_for_status()
    payload = resp.json()

    print(json.dumps(payload, indent=2))

    if args.strict and not payload.get("ready", False):
        sys.exit(2)


if __name__ == "__main__":
    main()
