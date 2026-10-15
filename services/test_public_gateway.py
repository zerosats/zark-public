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
from browser_policy import BrowserPolicy


class Core(BaseHTTPRequestHandler):
    requests = []
    raw_requests = []

    def log_message(self, *args):
        pass

    def do_POST(self):
        body = self.rfile.read(int(self.headers["Content-Length"]))
        self.raw_requests.append(body)
        # Model Core's first-member lookup, not Python's default last-member lookup.
        request = json.loads(body, object_pairs_hook=lambda items: dict(reversed(items)))
        self.requests.append((self.headers.get("Authorization"), request))
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
        Core.raw_requests = []
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

    def browser_request(self, method, path, body=None, headers=None):
        connection = http.client.HTTPConnection("127.0.0.1", self.gateway.server_port, timeout=3)
        connection.request(method, path, body, {"Content-Type": "application/json",
                           "Host": "chain.example.org", "Origin": "https://wallet.example.org", **(headers or {})})
        response = connection.getresponse()
        result = response.status, dict(response.getheaders()), response.read()
        connection.close()
        return result

    def enable_browser(self):
        self.gateway.browser_policy = BrowserPolicy(["https://wallet.example.org"], ["chain.example.org"])

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

    def test_duplicate_rpc_members_never_reach_core(self):
        self.enable_browser()
        bodies = []
        for field, first, second in [
                ("method", '"stop"', '"getblockchaininfo"'),
                ("params", '["unexpected"]', '[]'),
                ("id", '1', '2'),
                ("jsonrpc", '"1.0"', '"2.0"')]:
            for left, right in [(first, second), (second, first)]:
                base = '' if field == "method" else '"method":"getblockchaininfo",'
                bodies.append('{' + base + f'"{field}":{left},"{field}":{right}' + '}')
        observation_params = json.dumps(["1", "66" * 32, "0", "77" * 32, "2"])
        bodies.extend([
            r'{"method":"stop","m\u0065thod":"getblockchaininfo"}',
            '{"method":"getblockchaininfo","params":[{"x":1,"x":2}]}',
            '{"method":"zark_observe","params":' + observation_params + ',"params":' + observation_params + '}',
        ])
        for body in bodies:
            with self.subTest(body=body):
                self.assertEqual(self.request("POST", "/rpc", body)[0], 400)
                status, headers, _ = self.browser_request("POST", "/rpc", body)
                self.assertEqual(status, 400)
                self.assertEqual(headers["Access-Control-Allow-Origin"], "https://wallet.example.org")
                self.assertEqual(Core.raw_requests, [])

    def test_unique_rpc_members_preserve_exact_bytes_and_numeric_values(self):
        self.enable_browser()
        bodies = [
            b' { "params" : [], "id" : "native", "m\\u0065thod" : "getblockchaininfo" } ',
            b'{"method":"sendrawtransaction","params":["00",0.1234567890123456789],"id":9007199254740993}',
            b'{"jsonrpc":"2.0","method":"gettxout","params":["aa",0,true],"id":null}',
            b'{"method":"testmempoolaccept","params":[["00"],1e400]}',
        ]
        for body in bodies:
            with self.subTest(body=body):
                self.assertEqual(self.request("POST", "/rpc", body)[0], 200)
                self.assertEqual(Core.raw_requests[-1], body)
                self.assertEqual(self.browser_request("POST", "/rpc", body)[0], 200)
                self.assertEqual(Core.raw_requests[-1], body)

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

    def test_browser_origins_are_opt_in_and_rejected_before_core(self):
        body = json.dumps({"method": "getblockchaininfo", "params": []})
        self.assertEqual(self.browser_request("POST", "/rpc", body)[0], 403)
        self.enable_browser()
        for headers in [{"Origin": "null"}, {"Origin": "https://evil.example.org"},
                        {"Host": "evil.example.org"}, {"Content-Type": "text/plain"},
                        {"Authorization": "Basic private"}, {"Cookie": "private"}]:
            status, response_headers, _ = self.browser_request("POST", "/rpc", body, headers)
            self.assertIn(status, (403, 415))
            if status == 403:
                self.assertNotIn("Access-Control-Allow-Origin", response_headers)
        self.assertEqual(Core.requests, [])
        status, headers, reply = self.browser_request("POST", "/rpc", body)
        self.assertEqual(status, 200)
        self.assertEqual(headers["Access-Control-Allow-Origin"], "https://wallet.example.org")
        self.assertNotIn("Access-Control-Allow-Credentials", headers)
        self.assertEqual(json.loads(reply)["result"]["chain"], "signet")
        self.assertEqual(len(Core.requests), 1)

    def test_preflight_discovery_assets_and_errors_have_origin_headers(self):
        self.enable_browser()
        status, headers, body = self.browser_request("OPTIONS", "/rpc", headers={
            "Access-Control-Request-Method": "POST", "Access-Control-Request-Headers": "content-type"})
        self.assertEqual((status, body), (204, b""))
        self.assertEqual(headers["Access-Control-Allow-Methods"], "POST")
        self.assertEqual(self.browser_request("OPTIONS", "/rpc", headers={
            "Access-Control-Request-Method": "POST", "Access-Control-Request-Headers": "authorization"})[0], 400)
        status, headers, _ = self.browser_request("GET", "/health")
        self.assertEqual(status, 200)
        self.assertEqual(headers["X-Zark-Observation"], "1")
        self.assertIn("X-Zark-Observation", headers["Access-Control-Expose-Headers"])
        self.assertEqual(self.browser_request("GET", "/assets/public.bin")[2], b"authenticated")
        status, headers, _ = self.browser_request("POST", "/rpc", json.dumps({"method": "stop"}))
        self.assertEqual(status, 403)
        self.assertIn("Access-Control-Allow-Origin", headers)
        self.assertEqual(Core.requests, [])
        # Browser access does not expose the operator's coin-spending faucet.
        self.assertEqual(self.browser_request("POST", "/faucet", "{}")[0], 403)

    def test_browser_observation_keeps_evidence_and_tip_fences(self):
        self.enable_browser()
        params = ["1", "66" * 32, "0", "77" * 32, "2"]
        status, headers, body = self.browser_request("POST", "/rpc", json.dumps({
            "id": "browser", "method": "zark_observe", "params": params}))
        self.assertEqual(status, 200)
        self.assertIn("Access-Control-Allow-Origin", headers)
        reply = json.loads(body)
        self.assertEqual(reply["result"]["request"], params)
        self.assertEqual(reply["result"]["reads"][0]["method"], "getblockchaininfo")
        self.assertEqual(reply["result"]["reads"][-1]["method"], "getblockchaininfo")
        self.assertEqual(len(Core.requests), 7)

    def test_keepalive_never_leaks_another_requests_allowed_origin(self):
        self.enable_browser()
        connection = http.client.HTTPConnection("127.0.0.1", self.gateway.server_port, timeout=3)
        self.addCleanup(connection.close)
        for origin, status in [("https://wallet.example.org", 200), ("https://evil.example.org", 403)]:
            connection.request("GET", "/health", headers={"Host": "chain.example.org", "Origin": origin})
            response = connection.getresponse()
            self.assertEqual(response.status, status)
            self.assertEqual(response.getheader("Access-Control-Allow-Origin"), origin if status == 200 else None)
            response.read()

    def test_duplicate_lengths_and_encoded_bodies_never_reach_core(self):
        connection = http.client.HTTPConnection("127.0.0.1", self.gateway.server_port, timeout=3)
        self.addCleanup(connection.close)
        connection.putrequest("POST", "/rpc")
        connection.putheader("Content-Length", "2")
        connection.putheader("content-length", "2")
        connection.endheaders(b"{}")
        response = connection.getresponse()
        self.assertEqual(response.status, 413)
        response.read()
        self.assertEqual(self.request("POST", "/rpc", "{}", {"Content-Encoding": "gzip"})[0], 413)
        self.assertEqual(self.request("POST", "/rpc", "{}", {"Content-Length": "9" * 5000})[0], 413)
        self.assertEqual(Core.requests, [])

    def test_origin_configuration_is_exact_and_production_safe(self):
        for origin in ["*", "null", "https://wallet.example.org/", "https://wallet.example.org:443",
                       "http://wallet.example.org", "https://user@wallet.example.org", "https://x\r\nX: y"]:
            with self.assertRaises(ValueError, msg=origin):
                BrowserPolicy([origin], ["chain.example.org"])
        with self.assertRaises(ValueError):
            BrowserPolicy(["https://wallet.example.org"])
        BrowserPolicy(["http://127.0.0.1:5173"], ["localhost:8443"])


if __name__ == "__main__":
    unittest.main()
