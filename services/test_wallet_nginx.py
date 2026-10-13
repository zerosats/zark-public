"""Run the shipped nginx policy against a local synthetic bridge; no deployment."""
import concurrent.futures
import http.client
import json
import shutil
import socket
import ssl
import subprocess
import tempfile
import threading
import time
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

ORIGIN = "https://zark.lx.dev"


class FakeBridge(BaseHTTPRequestHandler):
    def log_message(self, *_):
        pass

    def do_POST(self):
        self.rfile.read(int(self.headers.get("Content-Length", "0")))
        self.server.headers.append(dict(self.headers))
        self.server.entered.set()
        self.server.release.wait(5)
        body = b'{"ok":true}'
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


@unittest.skipUnless(shutil.which("nginx"), "nginx needed for proxy integration tests")
class NginxTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="zark-nginx-")
        self.addCleanup(self.temp.cleanup)
        root = Path(self.temp.name)
        self.cert = root / "certificate.pem"
        key = root / "private.key"
        subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1",
                        "-subj", "/CN=zark-signer.lx.dev", "-addext", "subjectAltName=DNS:zark-signer.lx.dev,IP:127.0.0.1",
                        "-keyout", str(key), "-out", str(self.cert)], check=True, capture_output=True)
        self.bridge = ThreadingHTTPServer(("127.0.0.1", 0), FakeBridge)
        self.bridge.daemon_threads = True
        self.bridge.headers = []
        self.bridge.entered = threading.Event()
        self.bridge.release = threading.Event()
        self.bridge.release.set()
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(self.cert, key)
        self.bridge.socket = ctx.wrap_socket(self.bridge.socket, server_side=True)
        threading.Thread(target=self.bridge.serve_forever, daemon=True).start()
        self.addCleanup(self.bridge.server_close)
        self.addCleanup(self.bridge.shutdown)
        with socket.socket() as probe:
            probe.bind(("127.0.0.1", 0))
            self.port = probe.getsockname()[1]
        policy = Path(__file__).with_name("wallet-bridge.nginx.conf").read_text()
        policy = policy.replace("listen 443 ssl", f"listen 127.0.0.1:{self.port} ssl")
        policy = policy.replace("/etc/zark-wallet-bridge/tls/fullchain.pem", str(self.cert))
        policy = policy.replace("/etc/zark-wallet-bridge/tls/private.key", str(key))
        policy = policy.replace("/etc/ssl/certs/ca-certificates.crt", str(self.cert))
        policy = policy.replace("/var/log/nginx/zark-wallet-bridge-error.log", str(root / "error.log"))
        policy = policy.replace("127.0.0.1:7450", f"127.0.0.1:{self.bridge.server_port}")
        # One slot exercises the same policy without a 32-request stress test.
        policy = policy.replace("limit_conn zark_bridge_total 32", "limit_conn zark_bridge_total 1")
        config = root / "nginx.conf"
        config.write_text(f"pid {root}/nginx.pid; error_log {root}/main.log; events {{}} http {{ access_log off; client_body_temp_path {root}/body; proxy_temp_path {root}/proxy; {policy} }}")
        subprocess.run(["nginx", "-t", "-p", str(root), "-c", str(config)], check=True, capture_output=True)
        process = subprocess.Popen(["nginx", "-p", str(root), "-c", str(config), "-g", "daemon off;"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        def stop():
            self.bridge.release.set()
            process.terminate(); process.wait(timeout=10)
        self.addCleanup(stop)
        for _ in range(100):
            try:
                with socket.create_connection(("127.0.0.1", self.port), .1):
                    break
            except OSError:
                time.sleep(.02)
        else:
            self.fail("nginx did not start")

    def request(self, method="POST", origin=ORIGIN, extra=None):
        context = ssl.create_default_context(cafile=str(self.cert))
        client = http.client.HTTPSConnection("127.0.0.1", self.port, context=context, timeout=10)
        headers = {"Host": "zark-signer.lx.dev", "Origin": origin, "Content-Type": "application/json", "X-Zark-Browser-Demo": "1"}
        headers.update(extra or {})
        client.request(method, "/api/preview/faucet", b'{}' if method == "POST" else None, headers)
        response = client.getresponse()
        result = response.status, dict(response.getheaders()), response.read()
        client.close()
        return result

    def test_preflight_bypasses_busy_bridge_and_busy_response_is_readable(self):
        self.bridge.release.clear()
        with concurrent.futures.ThreadPoolExecutor() as pool:
            pending = pool.submit(self.request)
            self.assertTrue(self.bridge.entered.wait(5))
            code, headers, body = self.request(extra={"X-Forwarded-For": "192.0.2.9"})
            self.assertEqual(code, 429)
            self.assertEqual(json.loads(body)["code"], "overloaded")
            self.assertEqual(headers["Access-Control-Allow-Origin"], ORIGIN)
            self.assertEqual(headers["Access-Control-Expose-Headers"], "Retry-After")
            self.assertEqual(headers["Retry-After"], "2")
            code, headers, body = self.request("OPTIONS", extra={"Access-Control-Request-Method": "POST", "Access-Control-Request-Headers": "content-type,x-zark-browser-demo"})
            self.assertEqual(code, 204)
            self.assertEqual(headers["Access-Control-Allow-Origin"], ORIGIN)
            self.assertEqual(headers["Access-Control-Max-Age"], "600")
            self.assertEqual(body, b"")
            self.assertEqual(len(self.bridge.headers), 1)
            self.bridge.release.set()
            self.assertEqual(pending.result()[0], 200)

    def test_preflight_policy_and_forwarded_ip(self):
        for origin, extra in [("https://other.example", {"Access-Control-Request-Method": "POST"}),
                              (ORIGIN, {"Access-Control-Request-Method": "DELETE"}),
                              (ORIGIN, {"Access-Control-Request-Method": "POST", "Access-Control-Request-Headers": "Authorization"})]:
            self.assertEqual(self.request("OPTIONS", origin, extra)[0], 403)
        self.assertEqual(self.bridge.headers, [])
        self.assertEqual(self.request(extra={"X-Zark-Client-IP": "192.0.2.9", "X-Zark-Client": "spoof", "X-Real-IP": "192.0.2.8", "X-Forwarded-For": "192.0.2.7"})[0], 200)
        headers = {k.lower(): v for k, v in self.bridge.headers[-1].items()}
        self.assertEqual(headers["x-zark-client-ip"], "127.0.0.1")
        for name in ("x-zark-client", "x-real-ip", "x-forwarded-for"):
            self.assertNotIn(name, headers)

    def test_bridge_down_is_unavailable_not_busy(self):
        self.bridge.shutdown(); self.bridge.server_close()
        code, headers, body = self.request()
        self.assertEqual(code, 503)
        self.assertEqual(json.loads(body)["code"], "bridge_proxy_unavailable")
        self.assertEqual(headers["Access-Control-Allow-Origin"], ORIGIN)
        self.assertNotIn("Retry-After", headers)
