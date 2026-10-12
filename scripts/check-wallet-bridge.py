"""Read-only public PKI, CORS, deployment, chain and proof asset checks."""
import argparse
import hashlib
import json
import sys
import urllib.error
import urllib.request
from pathlib import Path


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *_args, **_kwargs):
        raise ValueError("bridge redirects are forbidden")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--url", default="https://zark-signer.lx.dev")
    parser.add_argument("--origin", default="https://zark.lx.dev")
    parser.add_argument("--pins", type=Path, required=True)
    parser.add_argument("--inventory", type=Path, required=True)
    args = parser.parse_args()
    if not args.url.startswith("https://") or args.url.endswith("/"):
        raise ValueError("expected HTTPS origin without trailing slash")
    pins, inventory = json.loads(args.pins.read_text()), json.loads(args.inventory.read_text())
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect())

    def request(path, method="POST", body=None, extra=None):
        headers = {"Origin": args.origin, "Content-Type": "application/json", "X-Zark-Browser-Demo": "1"}
        headers.update(extra or {})
        payload = json.dumps({} if body is None else body).encode() if method == "POST" else None
        return opener.open(urllib.request.Request(args.url + path, payload, headers, method=method), timeout=190)

    print("Checking public HTTPS and CORS preflight", flush=True)
    with request("/api/preview/status", "OPTIONS", extra={"Access-Control-Request-Method": "POST",
                 "Access-Control-Request-Headers": "Content-Type, X-Zark-Browser-Demo"}) as response:
        assert response.status == 204
        assert response.headers.get("Access-Control-Allow-Origin") == args.origin
        assert "x-zark-browser-demo" in response.headers.get("Access-Control-Allow-Headers", "").lower()
    print("Checking pinned deployment and mailbox health", flush=True)
    with request("/api/preview/status") as response:
        assert response.headers.get("Access-Control-Allow-Origin") == args.origin
        assert response.headers.get("Cache-Control") == "no-store"
        status = json.loads(response.read(65536))
        assert status["deploymentId"] == pins["deployment"]
        assert status["assetsReady"] is True and status["connected"] is True, status
    print("Checking pinned chain transport", flush=True)
    with request("/api/preview/chain", body={"method": "getblockchaininfo", "args": []}) as response:
        chain = json.loads(response.read(65536))
        assert chain["chain"] == "signet" and type(chain["blocks"]) is int
    print("Checking all 19 public proof asset hashes", flush=True)
    checked = 0
    for entry in inventory["files"]:
        if not entry["path"].startswith("suite/"):
            continue
        with request("/preview-assets/" + entry["path"], "GET") as response:
            assert response.headers.get("Access-Control-Allow-Origin") == args.origin
            digest, size = hashlib.sha256(), 0
            while chunk := response.read(1024 * 1024):
                size += len(chunk)
                assert size <= 512 * 1024 * 1024
                digest.update(chunk)
            assert digest.hexdigest() == entry["sha256"], entry["path"]
        checked += 1
    assert checked == 19
    try:
        with request("/api/preview/status", extra={"Origin": "https://denied.invalid"}):
            raise AssertionError("unexpected origin accepted")
    except urllib.error.HTTPError as error:
        assert error.code == 403
        assert error.headers.get("Access-Control-Allow-Origin") != "https://denied.invalid"
        error.close()
    print(json.dumps({"https_bridge_live": True, "url": args.url, "allowed_origin": args.origin,
                      "deployment": pins["deployment"], "suite": pins["suite"], "verified_assets": checked,
                      "mailbox_connected": True, "chain_blocks": chain["blocks"], "transfer_tested": False}))


if __name__ == "__main__":
    try:
        main()
    except Exception:
        print("Bridge verification failed; HTTPS is not yet qualified. Inspect service health and preserve wallet state.", file=sys.stderr)
        raise SystemExit(1)
