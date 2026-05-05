#!/usr/bin/env bash
# Emit env exports for Darkmesh AAuth writeback. Source this from your
# shell, e.g. `source scripts/aauth_env.sh mark_local`, then start the
# node. Requires secrets/<node>_darkmesh_private.jwk to exist (generate
# with `python -m darkmesh.aauth_signer keygen`).
set -euo pipefail

NODE_ID="${1:-mark_local}"
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PRIV="$ROOT/secrets/${NODE_ID}_darkmesh_private.jwk"

if [[ ! -f "$PRIV" ]]; then
  echo "Missing $PRIV. Generate with: python -m darkmesh.aauth_signer keygen --private-out $PRIV --public-out $ROOT/secrets/${NODE_ID}_darkmesh_public.jwk" >&2
  exit 1
fi

export DARKMESH_AAUTH_PRIVATE_JWK_PATH="$PRIV"
export DARKMESH_AAUTH_SUB="darkmesh-node@${NODE_ID}"
export DARKMESH_AAUTH_ISS="https://darkmesh.local"

# Phase 3: relay + peer + connector AAuth. Point the trust registry at
# the JSON file managed by `scripts/darkmesh_trust_add.py`, and let
# relays/nodes default to `auth_mode=either` so HMAC clients keep
# working during the migration.
TRUSTED_FILE_DEFAULT="$ROOT/config/trusted_agents.json"
export DARKMESH_TRUSTED_AGENTS_FILE="${DARKMESH_TRUSTED_AGENTS_FILE:-$TRUSTED_FILE_DEFAULT}"
export DARKMESH_RELAY_TRUSTED_AGENTS_FILE="${DARKMESH_RELAY_TRUSTED_AGENTS_FILE:-$DARKMESH_TRUSTED_AGENTS_FILE}"
export DARKMESH_AUTH_MODE="${DARKMESH_AUTH_MODE:-either}"
export DARKMESH_RELAY_AUTH_MODE="${DARKMESH_RELAY_AUTH_MODE:-either}"

echo "DARKMESH_AAUTH_PRIVATE_JWK_PATH=$DARKMESH_AAUTH_PRIVATE_JWK_PATH"
echo "DARKMESH_AAUTH_SUB=$DARKMESH_AAUTH_SUB"
echo "DARKMESH_AAUTH_ISS=$DARKMESH_AAUTH_ISS"
echo "DARKMESH_TRUSTED_AGENTS_FILE=$DARKMESH_TRUSTED_AGENTS_FILE"
echo "DARKMESH_RELAY_TRUSTED_AGENTS_FILE=$DARKMESH_RELAY_TRUSTED_AGENTS_FILE"
echo "DARKMESH_AUTH_MODE=$DARKMESH_AUTH_MODE"
echo "DARKMESH_RELAY_AUTH_MODE=$DARKMESH_RELAY_AUTH_MODE"

# Phase 2: AAuth writeback to Neotoma. Neotoma >= 0.9.0 (Stronger AAuth
# Admission release) requires that the identity above is bound to an
# `agent_grant` entity before any signed write or admission-aware read
# will succeed. We do not auto-provision here because creation requires
# the operator's Neotoma user-token, but we surface a one-line prompt so
# the next step is obvious. CI / fleet runners should call the
# provisioning script directly with --auto.
cat <<'HINT'

Next step (one-time per node, requires NEOTOMA_TOKEN):
  python scripts/neotoma_grants_provision.py --dry-run    # preview
  python scripts/neotoma_grants_provision.py --auto       # create or update
See docs/neotoma_integration.md for the full grants playbook.
HINT
