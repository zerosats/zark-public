#!/bin/bash
# Run as root from the explicit public-only deployment package.
set -euo pipefail
test "$(id -u)" = 0
bridge_source="$(cd -- "$(dirname -- "$0")/.." && pwd)"
test -f "$bridge_source/pins.json"
test -f "$bridge_source/inventory.json"
test ! -e /etc/nginx/sites-enabled/zark-wallet-bridge
test ! -e /etc/nginx/sites-available/zark-wallet-bridge
test ! -e /etc/systemd/system/zark-wallet-bridge.service
test ! -e /opt/zark-wallet-bridge
bridge_port="$(python3 - "${ZARK_BRIDGE_PORT:-}" <<'PY'
import socket, sys
requested = sys.argv[1]
if requested and (not requested.isascii() or not requested.isdecimal() or not 1024 <= int(requested) <= 65535):
    raise SystemExit("Invalid ZARK_BRIDGE_PORT")
candidates = [int(requested)] if requested else [7450, *range(17450, 17470)]
for port in candidates:
    with socket.socket() as listener:
        try:
            listener.bind(("127.0.0.1", port))
        except OSError:
            continue
        print(port)
        break
else:
    raise SystemExit("No available private bridge port; set ZARK_BRIDGE_PORT to a free port")
PY
 )"
printf 'Using private bridge port %s\n' "$bridge_port"
bridge_faucet_port="${ZARK_FAUCET_PORT:-}"
if [ -n "$bridge_faucet_port" ]; then
  python3 - "$bridge_faucet_port" <<'PYPORT'
import sys
port = sys.argv[1]
if not port.isascii() or not port.isdecimal() or not 1 <= int(port) <= 65535:
    raise SystemExit("Invalid ZARK_FAUCET_PORT")
PYPORT
fi
nginx -t
python3 -m unittest discover -s "$bridge_source/services" -p test_wallet_bridge.py
python3 - "$bridge_source/pins.json" <<'PY'
import json, subprocess, sys
with open(sys.argv[1]) as source:
    pins = json.load(source)
checked = subprocess.run([
    "runuser", "-u", "statechain-zark", "--", "sh", "-c",
    "cd /var/lib/statechain-zark && exec /opt/statechain-zark/bin/zark-signer --config /etc/statechain-zark/signer.json --check-config"
], capture_output=True, text=True)
if checked.returncode:
    raise SystemExit("Existing signer configuration check failed; installation stopped")
results = [json.loads(line) for line in checked.stdout.splitlines() if line.startswith("{")]
if not results or not all((results[-1].get("configuration_valid") is True,
                           results[-1].get("version") == 10,
                           results[-1].get("deployment") == pins["deployment"],
                           results[-1].get("suite") == pins["suite"])):
    raise SystemExit("Existing signer does not match the wallet pins; installation stopped")
print(json.dumps(results[-1]))
PY

if ! id zark-wallet-bridge >/dev/null 2>&1; then
  useradd --system --user-group --no-create-home --home-dir /nonexistent \
    --shell /usr/sbin/nologin zark-wallet-bridge
fi
install -d -m 755 /etc/zark-wallet-bridge
printf '%s\n' "$bridge_port" > /etc/zark-wallet-bridge/port
chmod 644 /etc/zark-wallet-bridge/port
if [ -n "$bridge_faucet_port" ]; then
  printf '%s\n' "$bridge_faucet_port" > /etc/zark-wallet-bridge/faucet-port
  chmod 644 /etc/zark-wallet-bridge/faucet-port
fi
install -m 755 "$bridge_source/services/wallet-bridge-run.sh" /usr/local/sbin/zark-wallet-bridge-run
install -m 755 "$bridge_source/services/wallet-bridge-tls-reload.sh" /usr/local/sbin/zark-wallet-bridge-tls-reload

# A fixed client release, no Certbot, no contact email, no profile changes.
# Explicit Let's Encrypt avoids the default CA's email/EAB enrollment.
install -d -m 700 /var/lib/zark-acme /var/lib/zark-acme/deployed
if ! test -f /var/lib/zark-acme/acme.sh; then
  curl -fL --proto '=https' --tlsv1.2 \
    https://github.com/acmesh-official/acme.sh/archive/refs/tags/3.1.6.tar.gz \
    -o "$bridge_source/acme.sh-3.1.6.tar.gz"
  tar -xzf "$bridge_source/acme.sh-3.1.6.tar.gz" -C "$bridge_source"
  (cd "$bridge_source/acme.sh-3.1.6" && sh ./acme.sh --install \
    --home /var/lib/zark-acme --no-cron --no-profile)
fi
sh /var/lib/zark-acme/acme.sh --home /var/lib/zark-acme --set-default-ca --server letsencrypt
if sh /var/lib/zark-acme/acme.sh --home /var/lib/zark-acme --issue --server letsencrypt --standalone \
  --keylength ec-256 -d zark-signer.lx.dev; then
  :
else
  bridge_acme_status="$?"
  # Exit 2 means an existing certificate is not due for renewal. Resume an
  # interrupted first installation without forcing another issuance.
  test "$bridge_acme_status" = 2 || exit "$bridge_acme_status"
  openssl x509 -in /var/lib/zark-acme/zark-signer.lx.dev_ecc/fullchain.cer \
    -noout -checkend 0 -checkhost zark-signer.lx.dev
fi
sh /var/lib/zark-acme/acme.sh --home /var/lib/zark-acme --install-cert --ecc -d zark-signer.lx.dev \
  --key-file /var/lib/zark-acme/deployed/private.key \
  --fullchain-file /var/lib/zark-acme/deployed/fullchain.pem \
  --reloadcmd /usr/local/sbin/zark-wallet-bridge-tls-reload

install -d -m 755 /opt/zark-wallet-bridge /opt/zark-wallet-bridge/services
for bridge_module in browser_policy.py wallet_assets.py wallet_transport.py wallet_bridge.py wallet_faucet.py; do
  install -m 644 "$bridge_source/services/$bridge_module" /opt/zark-wallet-bridge/services/
done
install -m 644 "$bridge_source/pins.json" "$bridge_source/inventory.json" \
  "$bridge_source/signer-certificate.pem" "$bridge_source/chain-certificate.pem" /opt/zark-wallet-bridge/
cp -a "$bridge_source/suite" /opt/zark-wallet-bridge/suite
chown -R root:root /opt/zark-wallet-bridge
chmod -R a+rX /opt/zark-wallet-bridge
runuser -u zark-wallet-bridge -- /usr/local/sbin/zark-wallet-bridge-run --check-config
install -m 644 "$bridge_source/services/zark-wallet-bridge.service" /etc/systemd/system/
systemctl daemon-reload
systemctl enable --now zark-wallet-bridge.service
sed "s/127.0.0.1:7450/127.0.0.1:$bridge_port/" "$bridge_source/services/wallet-bridge.nginx.conf" \
  > /etc/nginx/sites-available/zark-wallet-bridge
chmod 644 /etc/nginx/sites-available/zark-wallet-bridge
ln -s /etc/nginx/sites-available/zark-wallet-bridge /etc/nginx/sites-enabled/zark-wallet-bridge
if ! nginx -t; then
  unlink /etc/nginx/sites-enabled/zark-wallet-bridge
  exit 1
fi
systemctl reload nginx

cat > /etc/systemd/system/zark-acme-renew.service <<'UNIT'
[Unit]
Description=Renew Zark browser HTTPS certificate without email
After=network-online.target
[Service]
Type=oneshot
UMask=0077
ExecStart=/bin/sh /var/lib/zark-acme/acme.sh --cron --home /var/lib/zark-acme
UNIT
cat > /etc/systemd/system/zark-acme-renew.timer <<'UNIT'
[Unit]
Description=Daily Zark HTTPS certificate renewal check
[Timer]
OnCalendar=daily
RandomizedDelaySec=2h
Persistent=true
[Install]
WantedBy=timers.target
UNIT
systemctl daemon-reload
systemctl enable --now zark-acme-renew.timer
python3 "$bridge_source/scripts/check-wallet-bridge.py" \
  --pins "$bridge_source/pins.json" --inventory "$bridge_source/inventory.json"
