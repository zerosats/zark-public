#!/bin/sh
# ACME installs into a root-only staging area. Publish a validated pair at once.
set -eu
umask 077
bridge_tls_next="$(mktemp -d /etc/zark-wallet-bridge/tls-XXXXXXXX)"
chown zark-wallet-bridge:zark-wallet-bridge "$bridge_tls_next"
chmod 700 "$bridge_tls_next"
install -m 600 -o zark-wallet-bridge -g zark-wallet-bridge \
  /var/lib/zark-acme/deployed/fullchain.pem "$bridge_tls_next/fullchain.pem"
install -m 600 -o zark-wallet-bridge -g zark-wallet-bridge \
  /var/lib/zark-acme/deployed/private.key "$bridge_tls_next/private.key"
openssl x509 -in "$bridge_tls_next/fullchain.pem" -noout -checkend 0 -checkhost zark-signer.lx.dev
bridge_cert_pub="$(openssl x509 -in "$bridge_tls_next/fullchain.pem" -pubkey -noout)"
bridge_key_pub="$(openssl pkey -in "$bridge_tls_next/private.key" -pubout)"
test "$bridge_cert_pub" = "$bridge_key_pub"
bridge_tls_link="/etc/zark-wallet-bridge/tls.next.$$"
ln -s "$bridge_tls_next" "$bridge_tls_link"
mv -Tf "$bridge_tls_link" /etc/zark-wallet-bridge/tls
if systemctl is-active --quiet zark-wallet-bridge.service; then
  runuser -u zark-wallet-bridge -- /usr/local/sbin/zark-wallet-bridge-run --check-config
  systemctl reload zark-wallet-bridge.service
fi
nginx -t
systemctl reload nginx
