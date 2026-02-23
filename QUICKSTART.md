# Darkmesh Quickstart

Shortest path to run Darkmesh.

## Demo in 6 commands

```bash
git clone https://github.com/<owner>/<repo>.git
cd <repo>
python3 scripts/darkmesh_setup.py
python3 scripts/darkmesh_up.py --mode demo --relay-key demo-relay-key
python3 scripts/darkmesh_demo.py
python3 scripts/darkmesh_status.py --relay-url http://localhost:9000
```

Stop everything:

```bash
python3 scripts/darkmesh_down.py
```

## Real network in 5 steps

1. Start one relay host:

```bash
python3 scripts/run_darkmesh_relay.py --host 0.0.0.0 --port 9000 --relay-key <shared_relay_key>
```

2. Create node config on each node:

```bash
python3 scripts/darkmesh_init.py \
  --node-id <node_id> \
  --self-identifiers <email@domain.com> \
  --relay-url http://<relay-host>:9000 \
  --relay-key <shared_relay_key> \
  --output config/<node_id>.json
```

3. Start Darkmesh node + listener on each node:

```bash
python3 scripts/darkmesh_up.py --mode join --config config/<node_id>.json
```

4. Load integrations (pick one):

CSV path:

```bash
python3 connectors/contacts_csv.py --url http://localhost:8001 --file /path/to/contacts.csv
python3 connectors/interactions_csv.py --url http://localhost:8001 --file /path/to/interactions.csv
```

OpenClaw autodiscovery path:

```bash
export OPENCLAW_TOKEN=<token>
python3 connectors/openclaw_sync.py \
  --url http://localhost:8001 \
  --autodiscover \
  --openclaw-base-url http://localhost:3000 \
  --self-identifier <email@domain.com>
```

5. Verify integrations are loaded:

```bash
python3 scripts/darkmesh_integrations_check.py --url http://localhost:8001 --strict
```

Use from OpenClaw:

```text
Use $darkmesh to autodiscover OpenClaw integrations and ingest them into my node.
```
