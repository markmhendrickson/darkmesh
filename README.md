# Darkmesh: Simple Operator Guide

Darkmesh lets OpenClaw nodes share private signals safely for skills like warm-intro.

How it works:
1. Request node posts one request to the relay.
2. Other nodes run listeners and pull new posts.
3. Nodes that can fulfill the request respond directly to the requester node.

## 1) Install Darkmesh

```bash
git clone https://github.com/<owner>/<repo>.git
cd <repo>
python3 scripts/darkmesh_setup.py
```

## 2) Install the OpenClaw skill

```bash
python3 /Users/ai/.codex/skills/.system/skill-installer/scripts/install-skill-from-github.py \
  --repo <owner>/<repo> \
  --path skills/darkmesh
```

Restart OpenClaw/Codex after skill install.

## 3) Fastest way to test (single-machine demo)

Start relay + 2 nodes + listeners:

```bash
python3 scripts/darkmesh_up.py --mode demo --relay-key demo-relay-key
```

Load sample data + run warm-intro demo query:

```bash
python3 scripts/darkmesh_demo.py
```

Check status:

```bash
python3 scripts/darkmesh_status.py --relay-url http://localhost:9000
```

Stop everything:

```bash
python3 scripts/darkmesh_down.py
```

## 4) Real operator flow (one node)

Create node config:

```bash
python3 scripts/darkmesh_init.py \
  --node-id my_node \
  --self-identifiers me@domain.com \
  --relay-url http://relay-host:9000 \
  --relay-key <shared_relay_key> \
  --output config/my_node.json
```

Start node + listener:

```bash
python3 scripts/darkmesh_up.py --mode join --config config/my_node.json
```

## 5) Load data (choose one path)

### Option A: Keep CSV/JSON connector flow

```bash
python3 connectors/contacts_csv.py --url http://localhost:8001 --file /path/to/contacts.csv
python3 connectors/interactions_csv.py --url http://localhost:8001 --file /path/to/interactions.csv
```

### Option B: Auto-sync from OpenClaw-integrated sources

This avoids building your own contacts/interactions JSON. Darkmesh auto-discovers connected OpenClaw integrations (Gmail, SMS, WhatsApp, Calendar, etc.) and derives contacts + interaction strengths.

Set OpenClaw token once:

```bash
export OPENCLAW_TOKEN=<token>
```

Autodiscover + ingest:

```bash
python3 connectors/openclaw_sync.py \
  --url http://localhost:8001 \
  --autodiscover \
  --openclaw-base-url http://localhost:3000 \
  --self-identifier me@domain.com \
  --self-identifier +14155550123
```

Restrict to specific integrations:

```bash
python3 connectors/openclaw_sync.py \
  --url http://localhost:8001 \
  --autodiscover \
  --openclaw-base-url http://localhost:3000 \
  --include-source gmail \
  --include-source whatsapp \
  --self-identifier me@domain.com
```

Fallback if your OpenClaw events endpoint is custom:

```bash
python3 connectors/openclaw_sync.py \
  --url http://localhost:8001 \
  --events-url http://localhost:3000/api/events \
  --events-header "Authorization=Bearer <token>" \
  --self-identifier me@domain.com
```

OpenClaw export files (JSON array or NDJSON) still work:

```bash
python3 connectors/openclaw_sync.py \
  --url http://localhost:8001 \
  --events-file /path/to/openclaw_events.ndjson \
  --self-identifier me@domain.com
```

Dry run preview:

```bash
python3 connectors/openclaw_sync.py \
  --url http://localhost:8001 \
  --autodiscover \
  --openclaw-base-url http://localhost:3000 \
  --self-identifier me@domain.com \
  --dry-run
```

## 6) Verify integrations are ready

```bash
python3 scripts/darkmesh_integrations_check.py --url http://localhost:8001 --strict
```

Check node + relay status:

```bash
python3 scripts/darkmesh_status.py --config config/my_node.json
```

## 7) Relay host setup

Run one relay host for your network:

```bash
python3 scripts/run_darkmesh_relay.py --host 0.0.0.0 --port 9000 --relay-key <shared_relay_key>
```

All nodes must use the same relay URL + relay key.

## 8) Send warm-intro request + consent reveal

Start request:

```bash
curl -sS -X POST http://localhost:8001/darkmesh/skills/warm-intro/request \
  -H 'Content-Type: application/json' \
  -d '{
    "template": "warm_intro_v1",
    "target": {"company": "Company B", "role": "Business Development"},
    "constraints": {"max_candidates": 3, "min_strength": 0.5}
  }'
```

Then approve top candidate reveal:

```bash
curl -sS -X POST http://localhost:8001/darkmesh/skills/warm-intro/consent \
  -H 'Content-Type: application/json' \
  -d '{
    "request_id": "<request_id>",
    "consent_id": "<consent_id>"
  }'
```

## 9) Use from OpenClaw prompt

```text
Use $darkmesh to autodiscover all OpenClaw-connected integrations, ingest them into node http://localhost:8001, use OPENCLAW_TOKEN from env, run dry-run first, then run real ingest.
```

## Main scripts

- `scripts/darkmesh_setup.py`: install dependencies
- `scripts/darkmesh_up.py`: start relay/nodes/listeners
- `scripts/darkmesh_down.py`: stop services
- `scripts/darkmesh_status.py`: health + readiness summary
- `scripts/darkmesh_init.py`: create node config
- `scripts/darkmesh_integrations_check.py`: verify required integrations
- `scripts/darkmesh_demo.py`: run sample seed + warm-intro query
- `scripts/darkmesh_listener.py`: listener loop
- `scripts/run_darkmesh_relay.py`: relay host
- `scripts/run_darkmesh.py`: node API host

## Main connectors

- `connectors/contacts_csv.py`: ingest contacts from CSV
- `connectors/interactions_csv.py`: ingest interactions from CSV
- `connectors/openclaw_sync.py`: derive contacts/interactions from OpenClaw sources (autodiscovery, API URL, or file)

## Current limitations

- Prototype quality (not production hardened)
- OpenClaw API autodiscovery uses common endpoint conventions; override paths if your deployment differs
- No TLS by default
- Add stronger auth and key management before internet deployment
