#!/bin/sh
set -eu
# Opt in only when the existing loopback faucet is available. No credentials
# belong in this file; the faucet service retains its restricted RPC account.
if [ -f /etc/zark-wallet-bridge/faucet-port ]; then
  set -- --faucet-port "$(cat /etc/zark-wallet-bridge/faucet-port)" "$@"
fi
exec /usr/bin/python3 -B /opt/zark-wallet-bridge/services/wallet_bridge.py \
  --port "$(cat /etc/zark-wallet-bridge/port)" \
  --pins /opt/zark-wallet-bridge/pins.json \
  --inventory /opt/zark-wallet-bridge/inventory.json \
  --suite /opt/zark-wallet-bridge/suite \
  --signer-certificate /opt/zark-wallet-bridge/signer-certificate.pem \
  --chain-certificate /opt/zark-wallet-bridge/chain-certificate.pem \
  --certificate /etc/zark-wallet-bridge/tls/fullchain.pem \
  --private-key /etc/zark-wallet-bridge/tls/private.key "$@"
