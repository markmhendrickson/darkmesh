import json
import sys
from pathlib import Path

import requests

# Make local packages importable when script is run directly.
REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from connectors.contacts_csv import load_contacts
from connectors.interactions_csv import load_interactions


def ingest(base_url: str, csv_path: str) -> None:
    records = load_contacts(csv_path)
    payload = {"dataset": "contacts", "records": records}
    resp = requests.post(f"{base_url}/darkmesh/ingest", json=payload, timeout=10)
    resp.raise_for_status()
    print(json.dumps(resp.json(), indent=2))


def ingest_interactions(base_url: str, csv_path: str) -> None:
    records = load_interactions(csv_path)
    payload = {"dataset": "interactions", "records": records}
    resp = requests.post(f"{base_url}/darkmesh/ingest", json=payload, timeout=10)
    resp.raise_for_status()
    print(json.dumps(resp.json(), indent=2))


def main() -> None:
    if len(sys.argv) != 1:
        print("Usage: python3 scripts/darkmesh_demo_seed.py")
        sys.exit(1)

    ingest("http://localhost:8001", str(REPO_ROOT / "demo" / "node_a_contacts.csv"))
    ingest_interactions("http://localhost:8001", str(REPO_ROOT / "demo" / "node_a_interactions.csv"))
    ingest("http://localhost:8002", str(REPO_ROOT / "demo" / "node_b_contacts.csv"))
    ingest_interactions("http://localhost:8002", str(REPO_ROOT / "demo" / "node_b_interactions.csv"))


if __name__ == "__main__":
    main()
