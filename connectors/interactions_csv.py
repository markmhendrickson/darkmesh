import argparse
import csv
import json
from typing import List, Dict

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


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--url", required=True, help="Darkmesh node URL, e.g. http://localhost:8001")
    parser.add_argument("--file", required=True, help="CSV file path")
    args = parser.parse_args()

    records = load_interactions(args.file)
    payload = {"dataset": "interactions", "records": records}
    resp = requests.post(f"{args.url}/darkmesh/ingest", json=payload, timeout=10)
    resp.raise_for_status()
    print(json.dumps(resp.json(), indent=2))


if __name__ == "__main__":
    main()

