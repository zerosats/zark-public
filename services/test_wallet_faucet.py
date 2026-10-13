"""Local HTTP contract for sponsored deposits; no Core or funded wallet."""
import json
import threading
import unittest
from http.server import BaseHTTPRequestHandler, HTTPServer
from wallet_faucet import faucet_call


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *_):
        pass

    def do_GET(self):
        self.server.seen.append((self.command, self.path, self.headers.get("X-Zark-Client"), None))
        self.respond()

    def do_POST(self):
        body = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
        self.server.seen.append((self.command, self.path, self.headers.get("X-Zark-Client"), body))
        self.respond()

    def respond(self):
        raw = json.dumps(self.server.reply).encode()
        self.send_response(self.server.status)
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)


class FaucetAdapterTests(unittest.TestCase):
    def setUp(self):
        self.server = HTTPServer(("127.0.0.1", 0), Handler)
        self.server.status = 200
        self.server.reply = {"version": 1, "amount_sat": 25000, "available": True}
        self.server.seen = []
        threading.Thread(target=self.server.serve_forever, daemon=True).start()
        self.addCleanup(self.server.server_close)
        self.addCleanup(self.server.shutdown)

    def call(self, body):
        return faucet_call(self.server.server_port, body, "192.0.2.25")

    def test_status_and_exact_grant_forwarding(self):
        self.assertEqual(self.call({"method": "GET"}), (200, self.server.reply))
        self.server.reply = {"version": 1, "transaction": "00ff"}
        for _ in range(2):
            self.assertEqual(self.call({"method": "POST", "address": "saved"}), (200, self.server.reply))
        self.assertEqual(self.server.seen[1:], [("POST", "/faucet", "192.0.2.25", {"address": "saved"})] * 2)

    def test_daily_limit_and_empty_are_not_busy_and_unknown_detail_is_hidden(self):
        for code, status in (("daily_limit", 429), ("empty", 503), ("invalid_address", 400), ("PRIVATE_DETAIL", 503)):
            self.server.status = status
            self.server.reply = {"error": code}
            actual, reply = self.call({"method": "GET"})
            self.assertEqual(actual, status)
            self.assertNotEqual(reply["code"], "overloaded")
            self.assertNotIn("PRIVATE_DETAIL", json.dumps(reply))
        self.assertEqual(len(self.server.seen), 4)

    def test_unexpected_success_payload_is_not_exposed(self):
        for value in ({"version": 1, "amount_sat": 999, "available": True}, {"version": 1, "amount_sat": 25000, "available": True, "private": "hidden"}, []):
            self.server.reply = value
            with self.assertRaises(ValueError):
                self.call({"method": "GET"})
        self.server.reply = {"version": 1, "transaction": "xyz"}
        with self.assertRaises(ValueError):
            self.call({"method": "POST", "address": "saved"})
