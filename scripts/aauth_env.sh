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

echo "DARKMESH_AAUTH_PRIVATE_JWK_PATH=$DARKMESH_AAUTH_PRIVATE_JWK_PATH"
echo "DARKMESH_AAUTH_SUB=$DARKMESH_AAUTH_SUB"
echo "DARKMESH_AAUTH_ISS=$DARKMESH_AAUTH_ISS"
