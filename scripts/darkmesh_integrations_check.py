import argparse
import json
import sys

import requests


NODE_API_PREFIX = "/darkmesh"


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--url", required=True, help="Darkmesh node URL, e.g. http://localhost:8001")
    parser.add_argument("--strict", action="store_true", help="Exit non-zero when integrations are not ready")
    args = parser.parse_args()

    base_url = args.url.rstrip("/")
    resp = requests.get(f"{base_url}{NODE_API_PREFIX}/integrations/status", timeout=8)
    resp.raise_for_status()
    payload = resp.json()

    print(json.dumps(payload, indent=2))

    if args.strict and not payload.get("ready", False):
        sys.exit(2)


if __name__ == "__main__":
    main()
