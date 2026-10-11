import hashlib
import http.client
import json
import sys
import tempfile
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
from public_gateway import Gateway, public_assets


class Core(BaseHTTPRequestHandler):
    requests = []

    def log_message(self, *args):
        pass

    def do_POST(self):
        body = self.rfile.read(int(self.headers["Content-Length"]))
        self.requests.append((self.headers.get("Authorization"), json.loads(body)))
        request = json.loads(body)
        value = {"getblockchaininfo": {"chain": "signet", "blocks": 200, "bestblockhash": "44" * 32},
                 "getrawtransaction": {"confirmations": 100}, "getblockhash": "aa" * 32,
                 "gettxout": None}.get(request["method"])
        result = json.dumps({"result": value, "error": None, "id": 1}).encode()
        self.send_response(200)
        self.send_header("Content-Length", str(len(result)))
        self.end_headers()
        self.wfile.write(result)


class Faucet(BaseHTTPRequestHandler):
    requests = []

    def log_message(self, *args):
        pass

    def respond(self, body):
        self.requests.append((self.command, self.headers.get("X-Zark-Client"), body))
        result = b'{"ok": true}'
        self.send_response(200)
        self.send_header("Content-Length", str(len(result)))
        self.end_headers()
        self.wfile.write(result)

    def do_GET(self):
        self.respond(None)

    def do_POST(self):
        self.respond(self.rfile.read(int(self.headers["Content-Length"])))


def running(server):
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return thread


class GatewayTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        root = Path(self.temp.name)
        (root / "public.bin").write_bytes(b"authenticated")
        (root / "private-witness").write_bytes(b"secret")
        digest = hashlib.sha256(b"authenticated").hexdigest()
        manifest = root / "manifest.json"
        manifest.write_text(json.dumps({"version": 1, "files": [
            {"path": "public.bin", "sha256": digest},
        ]}))
        self.root, self.manifest = root, manifest
        Core.requests = []
        self.core = ThreadingHTTPServer(("127.0.0.1", 0), Core)
        running(self.core)
        self.addCleanup(self.core.server_close)
        self.addCleanup(self.core.shutdown)
        self.gateway = Gateway(("127.0.0.1", 0), public_assets(root, manifest),
                               b"gateway:private", self.core.server_port)
        running(self.gateway)
        self.addCleanup(self.gateway.server_close)
        self.addCleanup(self.gateway.shutdown)

    def request(self, method, path, body=None, headers=None):
        connection = http.client.HTTPConnection("127.0.0.1", self.gateway.server_port, timeout=3)
        connection.request(method, path, body, {"Content-Type": "application/json", **(headers or {})})
        response = connection.getresponse()
        result = response.status, response.read()
        connection.close()
        return result

    def test_only_listed_public_assets_are_served(self):
        self.assertEqual(self.request("GET", "/assets/public.bin"), (200, b"authenticated"))
        self.assertEqual(self.request("GET", "/assets/private-witness")[0], 404)
        self.assertEqual(self.request("GET", "/assets/../private-witness")[0], 404)

    def test_allowed_rpc_forwards_and_disallowed_rpc_never_reaches_core(self):
        allowed = json.dumps({"jsonrpc": "1.0", "id": 1,
                              "method": "getblockchaininfo", "params": []})
        self.assertEqual(self.request("POST", "/rpc", allowed)[0], 200)
        self.assertEqual(len(Core.requests), 1)
        self.assertEqual(Core.requests[0][0], "Basic Z2F0ZXdheTpwcml2YXRl")
        denied = json.dumps({"jsonrpc": "1.0", "id": 2, "method": "stop", "params": []})
        self.assertEqual(self.request("POST", "/rpc", denied)[0], 403)
        self.assertEqual(len(Core.requests), 1)

    def test_faucet_is_forwarded_with_gateway_client_address(self):
        self.assertEqual(self.request("GET", "/faucet")[0], 404)
        faucet = ThreadingHTTPServer(("127.0.0.1", 0), Faucet)
        running(faucet)
        self.addCleanup(faucet.server_close)
        self.addCleanup(faucet.shutdown)
        self.gateway.faucet_port = faucet.server_port
        Faucet.requests = []
        self.assertEqual(self.request("GET", "/faucet"), (200, b'{"ok": true}'))
        body = json.dumps({"address": "tb1p"})
        self.assertEqual(self.request("POST", "/faucet", body)[0], 200)
        self.assertEqual(Faucet.requests[1], ("POST", "127.0.0.1", body.encode()))
        self.assertEqual(self.request("POST", "/faucet", "x" * 5000)[0], 413)
        self.assertEqual(len(Core.requests), 0)

    def test_proxy_client_is_validated_and_direct_mode_ignores_spoofing(self):
        faucet = ThreadingHTTPServer(("127.0.0.1", 0), Faucet)
        running(faucet)
        self.addCleanup(faucet.server_close)
        self.addCleanup(faucet.shutdown)
        self.gateway.faucet_port = faucet.server_port
        Faucet.requests = []
        body = json.dumps({"address": "tb1p"})
        header = {"X-Zark-Client": "198.51.100.7"}
        self.assertEqual(self.request("POST", "/faucet", body, header)[0], 200)
        self.assertEqual(Faucet.requests[-1][1], "127.0.0.1")
        self.gateway.trusted_proxy = True
        self.assertEqual(self.request("POST", "/faucet", body, header)[0], 200)
        self.assertEqual(Faucet.requests[-1][1], "198.51.100.7")
        for headers in [{}, {"X-Zark-Client": "bad"}, {"X-Zark-Client": "127.0.0.1, 198.51.100.7"}]:
            self.assertEqual(self.request("POST", "/faucet", body, headers)[0], 400)
        self.assertEqual(len(Faucet.requests), 2)
        with self.assertRaisesRegex(ValueError, "loopback"):
            Gateway(("0.0.0.0", 0), {}, b"x:y", 1, trusted_proxy=True)

    def test_observation_collects_bounded_typed_reads_and_preserves_null(self):
        params = ["1", "66" * 32, "0", "77" * 32, "2"]
        status, body = self.request("POST", "/rpc", json.dumps({"id": 3, "method": "zark_observe", "params": params}))
        self.assertEqual(status, 200)
        reply = json.loads(body)
        self.assertEqual(reply["id"], 3)
        self.assertEqual(reply["result"]["request"], params)
        reads = reply["result"]["reads"]
        self.assertEqual(len(reads), 7)
        self.assertIsNone(reads[4]["result"])
        self.assertFalse(reads[4]["failed"])
        self.assertEqual([request["params"] for _, request in Core.requests],
                         [[], [0], [params[3], True], [101], [params[1], 0, True], [params[3], 2, True], []])
        self.assertEqual(self.request("POST", "/rpc", json.dumps({"method": "zark_observe", "params": params + ["stop"]}))[0], 400)
        self.assertEqual(len(Core.requests), 7)

    def test_tampered_asset_is_rejected_before_server_starts(self):
        (self.root / "public.bin").write_bytes(b"tampered")
        with self.assertRaisesRegex(ValueError, "hash mismatch"):
            public_assets(self.root, self.manifest)


if __name__ == "__main__":
    unittest.main()
