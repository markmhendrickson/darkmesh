import argparse
import csv
import json
from typing import List, Dict

import requests


def load_contacts(path: str) -> List[Dict]:
    records = []
    with open(path, "r", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for row in reader:
            record = {
                "name": row.get("name"),
                "email": (row.get("email") or "").strip().lower(),
                "org": row.get("org"),
                "role": row.get("role"),
            }
            if row.get("strength"):
                try:
                    record["strength"] = float(row["strength"])
                except ValueError:
                    record["strength"] = 0.5
            records.append(record)
    return records


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--url", required=True, help="Darkmesh node URL, e.g. http://localhost:8001")
    parser.add_argument("--file", required=True, help="CSV file path")
    args = parser.parse_args()

    records = load_contacts(args.file)
    payload = {"dataset": "contacts", "records": records}
    resp = requests.post(f"{args.url}/darkmesh/ingest", json=payload, timeout=10)
    resp.raise_for_status()
    print(json.dumps(resp.json(), indent=2))


if __name__ == "__main__":
    main()

