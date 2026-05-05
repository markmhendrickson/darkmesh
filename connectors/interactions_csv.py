"""CSV -> Darkmesh interactions ingest connector.

See :mod:`connectors.contacts_csv` for AAuth notes; this connector uses
the sub ``connector-csv-interactions@<operator>``.
"""

from __future__ import annotations

import argparse
import json
import os
import csv
from typing import Dict, List

from connectors._auth import ConnectorAuth, add_auth_arguments


CONNECTOR_SUB_PREFIX = "connector-csv-interactions"


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


def _default_sub() -> str:
    operator = (
        os.environ.get("DARKMESH_NODE_ID")
        or os.environ.get("DARKMESH_OPERATOR")
        or "local"
    )
    return f"{CONNECTOR_SUB_PREFIX}@{operator}"


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--url", required=True, help="Darkmesh node URL, e.g. http://localhost:8001")
    parser.add_argument("--file", required=True, help="CSV file path")
    add_auth_arguments(parser, default_sub=_default_sub())
    args = parser.parse_args()

    auth = ConnectorAuth.from_args(args, default_sub=_default_sub())
    records = load_interactions(args.file)
    payload = {"dataset": "interactions", "records": records}
    resp = auth.post(f"{args.url.rstrip('/')}/darkmesh/ingest", payload, timeout=10)
    resp.raise_for_status()
    print(json.dumps(resp.json(), indent=2))


if __name__ == "__main__":
    main()
