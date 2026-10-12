"""Synthetic HTTPS, pinning, framing and browser-policy regressions."""
import hashlib
import http.client
import json
import socket
import ssl
import subprocess
import sys
import tempfile
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
from browser_policy import BrowserPolicy
from wallet_assets import NAMES, PublicSuite
from wallet_bridge import Bridge, server_context
from wallet_transport import NativeTransport, chain_params, decode_json, validate_call

ROOT = Path(__file__).resolve().parents[1]
ORIGIN = "https://zark.lx.dev"
HOST = "zark-signer.lx.dev"


def serve(server):
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()


class NativeServer:
    def __init__(self, context):
        self.context = context
        self.requests = []
        self.reply = b'{"ok":true,"result":{"native":true}}\n'
        self.listener = socket.socket()
        self.listener.bind(("127.0.0.1", 0))
        self.listener.listen()
        self.port = self.listener.getsockname()[1]
        self.stopped = threading.Event()
        self.listener.settimeout(.1)
        threading.Thread(target=self.run, daemon=True).start()

    def run(self):
        while not self.stopped.is_set():
            try:
                raw, _ = self.listener.accept()
            except socket.timeout:
                continue
            except OSError:
                return
            try:
                with self.context.wrap_socket(raw, server_side=True) as connection:
                    connection.settimeout(2)
                    chunks = bytearray()
                    while b"\n" not in chunks:
                        chunk = connection.recv(65536)
                        if not chunk:
                            break
                        chunks.extend(chunk)
                    if chunks:
                        self.requests.append((connection.selected_alpn_protocol(), bytes(chunks)))
                        if self.reply is not None:
                            connection.sendall(self.reply)
            except OSError:
                raw.close()

    def close(self):
        self.stopped.set()
        self.listener.close()


class ChainHandler(BaseHTTPRequestHandler):
    def log_message(self, *_):
        pass

    def respond(self, payload):
        self.send_response(200)
        self.send_header("Content-Length", str(len(payload)))
        self.send_header("Connection", "close")
        if self.server.advertise:
            self.send_header("X-Zark-Observation", "1")
        self.end_headers()
        self.wfile.write(payload)

    def do_GET(self):
        self.respond(b'{"ok":true}')

    def do_POST(self):
        body = decode_json(self.rfile.read(int(self.headers["Content-Length"])))
        self.server.requests.append((self.headers["Host"], body))
        self.respond(json.dumps({"result": {"chain": "signet", "zark_observation_version": 99},
                                 "error": None}).encode())


class BridgeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        (ROOT / "work").mkdir(exist_ok=True)
        cls.temp = tempfile.TemporaryDirectory(prefix="wallet-bridge-tests-", dir=ROOT / "work")
        cls.root = Path(cls.temp.name)
        for target, name in (("signer", "signer.internal"), ("chain", "chain.internal"), ("browser", HOST)):
            subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1",
                            "-subj", "/CN=" + name, "-addext", "subjectAltName=DNS:" + name + ",IP:127.0.0.1",
                            "-keyout", str(cls.root / (target + ".key")), "-out", str(cls.root / (target + ".pem"))],
                           check=True, capture_output=True)

    @classmethod
    def tearDownClass(cls):
        cls.temp.cleanup()

    def context(self, target, protocols):
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(self.root / (target + ".pem"), self.root / (target + ".key"))
        context.set_alpn_protocols(protocols)
        return context

    def setUp(self):
        self.native = NativeServer(self.context("signer", ["statechain/10", "zark-mail/1"]))
        self.addCleanup(self.native.close)
        self.chain = ThreadingHTTPServer(("127.0.0.1", 0), ChainHandler)
        self.chain.requests, self.chain.advertise = [], True
        self.chain.socket = self.context("chain", ["http/1.1"]).wrap_socket(self.chain.socket, server_side=True)
        serve(self.chain)
        self.addCleanup(self.chain.server_close)
        self.addCleanup(self.chain.shutdown)
        pin = lambda target: hashlib.sha256(ssl.PEM_cert_to_DER_cert((self.root / (target + ".pem")).read_text())).hexdigest()
        self.pins = {"version": 10, "name": "Synthetic v10", "deployment": "aa" * 32, "suite": "bb" * 32,
                     "certificate_sha256": pin("signer"), "signer": {"port": self.native.port, "server_name": "signer.internal"},
                     "chain": {"port": self.chain.server_port, "server_name": "chain.internal", "certificate_sha256": pin("chain")}}
        self.suite = self.root / "suite"
        files = []
        for name in sorted(NAMES):
            filename = self.root / name
            filename.parent.mkdir(parents=True, exist_ok=True)
            payload = b'{"synthetic":true}' if name.endswith(".json") else b"synthetic public VK"
            filename.write_bytes(payload)
            files.append({"path": name, "sha256": hashlib.sha256(payload).hexdigest()})
        self.pins["manifest_sha256"] = next(item["sha256"] for item in files if item["path"] == "suite/suite-manifest.json")
        self.inventory = self.root / "inventory.json"
        self.inventory.write_text(json.dumps({"version": 1, "protocol_version": 10, "complete": True, "files": files}))
        self.assets = PublicSuite(self.suite, self.inventory, self.pins)
        self.transport = NativeTransport(self.pins, self.root / "signer.pem", self.root / "chain.pem")
        self.bridge = Bridge(("127.0.0.1", 0), self.transport, self.assets, self.pins,
                             BrowserPolicy([ORIGIN], [HOST]), self.context("browser", ["http/1.1"]))
        serve(self.bridge)
        self.addCleanup(self.bridge.server_close)
        self.addCleanup(self.bridge.shutdown)

    def request(self, route="status", body=None, method="POST", headers=None):
        context = ssl.create_default_context(cafile=str(self.root / "browser.pem"))
        connection = http.client.HTTPSConnection("127.0.0.1", self.bridge.server_port, context=context, timeout=10)
        values = {"Host": HOST, "Origin": ORIGIN, "X-Zark-Browser-Demo": "1", "Content-Type": "application/json"}
        values.update(headers or {})
        path = route if route.startswith("/") else "/api/preview/" + route
        payload = json.dumps({} if body is None else body).encode() if method == "POST" else None
        connection.request(method, path, payload, values)
        response = connection.getresponse()
        result = response.status, dict(response.getheaders()), response.read()
        connection.close()
        return result

    def test_preflight_and_status(self):
        code, headers, raw = self.request(method="OPTIONS", headers={"Access-Control-Request-Method": "POST",
                                      "Access-Control-Request-Headers": "Content-Type, X-Zark-Browser-Demo"})
        self.assertEqual(code, 204)
        self.assertEqual(headers["Access-Control-Allow-Origin"], ORIGIN)
        self.assertIn("X-Zark-Browser-Demo", headers["Access-Control-Allow-Headers"])
        self.assertEqual(raw, b"")
        code, headers, raw = self.request()
        self.assertEqual(code, 200)
        self.assertEqual(headers["Cache-Control"], "no-store")
        self.assertEqual(decode_json(raw), {"deployment": "Synthetic v10", "deploymentId": "aa" * 32,
                                           "assetsReady": True, "connected": True, "issues": []})

    def test_cors_and_credentials_denied_before_native_write(self):
        for headers in ({"Origin": "https://evil.example"}, {"Host": "evil.example"}, {"Cookie": "session=secret"},
                        {"Authorization": "secret"}, {"X-Zark-Browser-Demo": "0"}, {"Content-Encoding": "gzip"}):
            code, response_headers, _ = self.request(headers=headers)
            self.assertEqual(code, 403)
            if headers.get("Origin") == "https://evil.example":
                self.assertNotIn("Access-Control-Allow-Origin", response_headers)
        self.assertEqual(self.native.requests, [])

    def test_exact_inner_signer_string_and_unwrapped_response(self):
        inner = ' { "proof" : "a\\nb", "unicode":"λ" } '
        body = {"method": "zark_request", "request": inner}
        code, _, raw = self.request("signer", body)
        self.assertEqual(code, 200)
        self.assertEqual(decode_json(raw), {"ok": True, "result": {"native": True}})
        protocol, sent = self.native.requests[0]
        self.assertEqual(protocol, "statechain/10")
        self.assertEqual(decode_json(sent)["request"], inner)

    def test_ambiguous_native_failure_is_not_retried(self):
        self.native.reply = None  # Simulates a commit followed by a lost reply.
        code, headers, raw = self.request("mail", {"version": 1, "method": "POST", "path": "/v1/mailboxes", "body": {}})
        self.assertEqual(code, 503)
        self.assertEqual(len(self.native.requests), 1)
        self.assertEqual(headers["Access-Control-Allow-Origin"], ORIGIN)
        self.assertEqual(decode_json(raw)["code"], "bridge_unavailable")

    def test_native_alpn_mismatch_never_transmits_request(self):
        self.native.context.set_alpn_protocols(["unrelated/1"])
        with self.assertRaises(ssl.SSLError):
            self.transport.exchange({"method": "zark_request", "request": "{}"}, "statechain/10")
        self.assertEqual(self.native.requests, [])

    def test_peer_pin_mismatch_never_transmits_request(self):
        self.transport.pins["certificate_sha256"] = "00" * 32
        with self.assertRaises(ssl.SSLError):
            self.transport.exchange({"method": "zark_request", "request": "{}"}, "statechain/10")
        self.assertEqual(self.native.requests, [])

    def test_private_tls_key_permissions_are_required(self):
        key = self.root / "browser.key"
        key.chmod(0o644)
        with self.assertRaises(ValueError):
            server_context(self.root / "browser.pem", key)
        key.chmod(0o600)
        self.root.chmod(0o700)
        self.assertIsInstance(server_context(self.root / "browser.pem", key), ssl.SSLContext)

    def test_native_framing_failure_is_safe(self):
        self.native.reply = b'{"ok":true}\n{"extra":true}\n'
        code, _, raw = self.request("signer", {"method": "zark_request", "request": "{}"})
        self.assertEqual(code, 503)
        self.assertNotIn(b"extra", raw)
        self.assertEqual(len(self.native.requests), 1)

    def test_chain_result_conversion_and_verified_capability(self):
        self.assertEqual(self.transport.chain_call({"method": "getblockchaininfo", "args": []}),
                         {"chain": "signet", "zark_observation_version": 1})
        code, _, raw = self.request("chain", {"method": "getblockchaininfo", "args": []})
        self.assertEqual(code, 200)
        self.assertEqual(decode_json(raw), {"chain": "signet", "zark_observation_version": 1})
        self.assertEqual(self.chain.requests[0][0], "chain.internal:" + str(self.chain.server_port))
        self.chain.advertise = False
        code, _, raw = self.request("chain", {"method": "getblockchaininfo", "args": []})
        self.assertEqual(code, 200)
        self.assertNotIn("zark_observation_version", decode_json(raw))
        self.request("chain", {"method": "gettxout", "args": ["aa" * 32, "2", "true"]})
        self.assertEqual(self.chain.requests[-1][1]["params"], ["aa" * 32, 2, True])

    def test_asset_allowlist_pin_and_snapshot(self):
        path = "/preview-assets/suite/deposit_authorization/vk"
        code, headers, raw = self.request(path, method="GET")
        self.assertEqual(code, 200)
        self.assertEqual(headers["Access-Control-Allow-Origin"], ORIGIN)
        self.assertEqual(raw, b"synthetic public VK")
        snapshot, _ = self.assets.authenticated("suite/deposit_authorization/vk")
        (self.suite / "deposit_authorization/vk").write_bytes(b"replaced")
        with snapshot:
            self.assertEqual(snapshot.read(), b"synthetic public VK")
        self.assertEqual(self.request(path, method="GET")[0], 503)
        for name in ("../signer.key", "certificate.pem", "suite/../signer.key", "suite/suite-manifest.json?download=1"):
            self.assertEqual(self.request("/preview-assets/" + name, method="GET")[0], 404)

    def test_mismatched_certificates_and_incomplete_inventory_fail_closed(self):
        with self.assertRaises(ValueError):
            NativeTransport(self.pins, self.root / "chain.pem", self.root / "chain.pem")
        inventory = decode_json(self.inventory.read_bytes())
        inventory["files"].pop()
        self.inventory.write_text(json.dumps(inventory))
        with self.assertRaises(ValueError):
            PublicSuite(self.suite, self.inventory, self.pins)

    def test_route_and_json_restrictions(self):
        for body in ({"method": "sendrawtransaction", "args": ["00"]}, {"method": "getblockhash", "args": ["-1"]}):
            self.assertEqual(self.request("chain", body)[0], 400)
        self.assertEqual(self.chain.requests, [])
        self.assertEqual(self.request("mail", {"version": 1, "method": "POST", "path": "/v1/offers", "body": {}})[0], 400)
        for raw in (b'{"a":1,"a":2}', b'{"a":NaN}', b'"\xff"'):
            with self.assertRaises((ValueError, UnicodeError)):
                decode_json(raw)
        self.assertEqual(chain_params("testmempoolaccept", ['["abcd"]']), [["abcd"]])
        for method, args in (("getrawtransaction", ["aa", "1"]), ("zark_observe", ["1", "aa" * 32, "0", "bb" * 32, "4294967296"])):
            with self.assertRaises(ValueError):
                chain_params(method, args)
        with self.assertRaises(ValueError):
            validate_call("signer", {"method": "zark_request", "request": "{}", "target": "evil"})


if __name__ == "__main__":
    unittest.main()
