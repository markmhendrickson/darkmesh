import json

import requests


NODE_URL = "http://localhost:8001"


def main() -> None:
    payload = {
        "template": "warm_intro_v1",
        "target": {"company": "Company X", "role": "Business Development"},
        "constraints": {"max_candidates": 3, "min_strength": 0.5},
    }
    resp = requests.post(f"{NODE_URL}/darkmesh/skills/warm-intro/request", json=payload, timeout=20)
    resp.raise_for_status()
    result = resp.json()
    print(json.dumps(result, indent=2))

    candidates = result.get("candidates") or []
    if not candidates:
        return

    top = candidates[0]
    consent_id = top.get("consent_id")
    if not consent_id:
        return

    consent_payload = {
        "request_id": result["request_id"],
        "consent_id": consent_id,
    }
    consent_resp = requests.post(f"{NODE_URL}/darkmesh/skills/warm-intro/consent", json=consent_payload, timeout=20)
    consent_resp.raise_for_status()

    print()
    print(json.dumps(consent_resp.json(), indent=2))


if __name__ == "__main__":
    main()
