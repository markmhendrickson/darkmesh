"""CSV -> Darkmesh contacts ingest connector.

Phase 3: when AAuth env material is configured (or ``--auth-mode aauth``
is passed), the connector signs its ``POST /darkmesh/ingest`` request
with RFC 9421 + ``aa-agent+jwt`` under the sub
``connector-csv-contacts@<operator>`` so the node can authorise the
connector independently of its own node keypair.
"""

from __future__ import annotations

import argparse
import csv
import json
import os
from typing import Dict, List

from connectors._auth import ConnectorAuth, add_auth_arguments


CONNECTOR_SUB_PREFIX = "connector-csv-contacts"


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
    records = load_contacts(args.file)
    payload = {"dataset": "contacts", "records": records}
    resp = auth.post(f"{args.url.rstrip('/')}/darkmesh/ingest", payload, timeout=10)
    resp.raise_for_status()
    print(json.dumps(resp.json(), indent=2))


if __name__ == "__main__":
    main()
