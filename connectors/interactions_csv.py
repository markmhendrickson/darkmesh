import argparse
import csv
import json
import os
from typing import Dict, List

import requests


def load_interactions(path: str) -> List[Dict]:
    records = []
    with open(path, "r", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for row in reader:
            email = (row.get("email") or "").strip().lower()
            if not email:
                continue
            try:
                strength = float(row.get("strength", 0.5))
            except ValueError:
                strength = 0.5
            records.append({"email": email, "strength": strength})
    return records


def node_headers(node_key: str) -> Dict[str, str]:
    token = node_key.strip()
    if not token:
        raise SystemExit("node key is required (pass --node-key or set DARKMESH_NODE_KEY)")
    return {"X-Darkmesh-Key": token}


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--url", required=True, help="Darkmesh node URL, e.g. http://localhost:8001")
    parser.add_argument("--file", required=True, help="CSV file path")
    parser.add_argument("--node-key", default=os.environ.get("DARKMESH_NODE_KEY", ""))
    args = parser.parse_args()

    records = load_interactions(args.file)
    payload = {"dataset": "interactions", "records": records}
    resp = requests.post(
        f"{args.url}/darkmesh/ingest",
        json=payload,
        headers=node_headers(args.node_key),
        timeout=10,
    )
    resp.raise_for_status()
    print(json.dumps(resp.json(), indent=2))


if __name__ == "__main__":
    main()
