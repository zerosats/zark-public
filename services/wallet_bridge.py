"""Production browser adapter: HTTPS ingress, pinned native egress, public assets."""
import argparse
import http.client
import ipaddress
import os
import shutil
import signal
import ssl
import stat
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from browser_policy import BrowserPolicy
from wallet_assets import PublicSuite
from wallet_transport import LIMIT, NativeTransport, decode_json, encode_json, validate_call

ROUTES = {"/api/preview/" + name: name for name in ("status", "signer", "mail", "chain")}
SAFE_ERROR = {"code": "bridge_unavailable", "error": "Pinned transport or proof assets unavailable. Preserve the wallet and resume the saved operation."}


def server_context(certificate, private_key):
    key, parent = Path(private_key).resolve(strict=True), Path(private_key).resolve(strict=True).parent
    info, directory = key.stat(), parent.stat()
    if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid() or stat.S_IMODE(info.st_mode) != 0o600
            or directory.st_uid != os.geteuid() or stat.S_IMODE(directory.st_mode) != 0o700):
        raise ValueError("TLS key must be owned mode 0600 in an owned mode 0700 directory")
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.load_cert_chain(certificate, private_key)
    context.set_alpn_protocols(["http/1.1"])
    return context


class Bridge(ThreadingHTTPServer):
    daemon_threads = True
    request_queue_size = 32

    def __init__(self, address, transport, assets, pins, policy, tls_context):
        if not ipaddress.ip_address(address[0]).is_loopback:
            raise ValueError("bridge must bind to loopback behind the controlled HTTPS proxy")
        self.transport, self.assets, self.pins = transport, assets, pins
        self.policy, self.tls_context = policy, tls_context
        self.slots = threading.BoundedSemaphore(32)
        self.chain_slots = threading.BoundedSemaphore(4)
        super().__init__(address, Handler)

    def process_request(self, request, client_address):
        if not self.slots.acquire(blocking=False):
            self.shutdown_request(request)
            return
        try:
            super().process_request(request, client_address)
        except BaseException:
            self.slots.release()
            raise

    def process_request_thread(self, request, client_address):
        try:
            request.settimeout(8)
            # TLS handshakes run under the same bounded admission as HTTP work;
            # a stalled handshake must not block the listener's accept loop.
            with self.tls_context.wrap_socket(request, server_side=True) as secure:
                super().process_request_thread(secure, client_address)
        except (OSError, ssl.SSLError):
            request.close()
        finally:
            self.slots.release()

    def handle_error(self, request, client_address):
        pass  # Never print payloads, mailbox bearer tokens or upstream errors.


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.0"
    server_version = "ZarkBridge/1"
    sys_version = ""
    timeout = 8
    disable_nagle_algorithm = True

    def log_message(self, *_):
        pass

    def end_headers(self):
        self.send_header("Vary", "Origin")
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        if getattr(self, "cors_origin", None):
            self.send_header("Access-Control-Allow-Origin", self.cors_origin)
        super().end_headers()

    def reply(self, status, body):
        raw = encode_json(body)
        self.connection.settimeout(15)
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)

    def send_error(self, code, message=None, explain=None):
        self.close_connection = True
        self.reply(code, {"code": "http_request_denied", "error": "Request denied"})

    def access(self, *, asset=False):
        self.cors_origin = None
        origins = self.headers.get_all("Origin", [])
        hosts = self.headers.get_all("Host", [])
        if (len(hosts) != 1 or hosts[0] not in self.server.policy.hosts
                or (origins != [] and (len(origins) != 1 or origins[0] not in self.server.policy.origins))
                or (not asset and not origins)
                or any(self.headers.get_all(name) for name in
                       ("Cookie", "Authorization", "Content-Encoding", "Transfer-Encoding", "Expect"))):
            self.reply(403, {"code": "browser_request_denied", "error": "Browser request denied"})
            return False
        if origins:
            self.cors_origin = origins[0]
        elif asset:
            self.cors_origin = next(iter(self.server.policy.origins))
        return True

    def do_OPTIONS(self):
        if not self.access():
            return
        method = "POST" if self.path in ROUTES else "GET" if self.asset_name() else None
        requested = self.headers.get_all("Access-Control-Request-Method", [])
        headers = self.headers.get_all("Access-Control-Request-Headers", [])
        names = [name.strip().lower() for value in headers for name in value.split(",")]
        if (method is None or requested != [method] or len(headers) > 1
                or any(name not in ("content-type", "x-zark-browser-demo") for name in names)
                or self.headers.get_all("Content-Length", []) not in ([], ["0"])):
            return self.reply(400, {"code": "invalid_preflight", "error": "Invalid preflight"})
        self.send_response(204)
        self.send_header("Content-Length", "0")
        self.send_header("Access-Control-Allow-Methods", "POST, GET, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type, X-Zark-Browser-Demo")
        self.send_header("Access-Control-Max-Age", "60")
        self.end_headers()

    def asset_name(self):
        if self.path.startswith("/preview-assets/"):
            name = self.path[len("/preview-assets/"):]
            if name in self.server.assets.hashes:
                return name
        return None

    def do_GET(self):
        if not self.access(asset=True):
            return
        name = self.asset_name()
        if not name:
            return self.reply(404, {"code": "not_found", "error": "Unknown public asset"})
        try:
            snapshot, size = self.server.assets.authenticated(name)
        except (OSError, ValueError):
            return self.reply(503, SAFE_ERROR)
        with snapshot:
            self.connection.settimeout(30)
            self.send_response(200)
            self.send_header("Content-Type", "application/json" if name.endswith(".json") else "application/octet-stream")
            self.send_header("Content-Length", str(size))
            self.end_headers()
            shutil.copyfileobj(snapshot, self.wfile, 65536)

    def read_body(self):
        lengths = self.headers.get_all("Content-Length", [])
        if (len(lengths) != 1 or len(lengths[0]) > 7 or not lengths[0].isascii()
                or not lengths[0].isdecimal() or not 0 < int(lengths[0]) <= LIMIT):
            raise ValueError("invalid body size")
        deadline, remaining, chunks = time.monotonic() + 8, int(lengths[0]), bytearray()
        while remaining:
            timeout = deadline - time.monotonic()
            if timeout <= 0:
                raise TimeoutError("upload deadline")
            self.connection.settimeout(timeout)
            chunk = self.rfile.read1(min(remaining, 65536))
            if not chunk:
                raise OSError("incomplete upload")
            chunks.extend(chunk)
            remaining -= len(chunk)
        return decode_json(bytes(chunks))

    def do_POST(self):
        if not self.access():
            return
        if self.path not in ROUTES:
            return self.reply(404, {"code": "not_found", "error": "Unknown API route"})
        if (self.headers.get_all("X-Zark-Browser-Demo", []) != ["1"]
                or self.headers.get_all("Content-Type", []) not in
                (["application/json"], ["application/json; charset=utf-8"])):
            return self.reply(403, {"code": "browser_request_denied", "error": "Invalid browser headers"})
        route = ROUTES[self.path]
        try:
            body = self.read_body()
            validate_call(route, body)
        except (ValueError, RecursionError, UnicodeError):
            return self.reply(400, {"code": "invalid_request", "error": "Invalid browser request"})
        except OSError:
            return self.reply(408, {"code": "incomplete_request", "error": "Incomplete browser request"})
        try:
            if route == "status":
                result = self.status()
            elif route == "chain":
                if not self.server.chain_slots.acquire(blocking=False):
                    return self.reply(429, {"code": "bridge_busy", "error": "Bridge busy; resume the saved operation later"})
                try:
                    result = self.server.transport.chain_call(body)
                finally:
                    self.server.chain_slots.release()
            else:
                protocol = "statechain/10" if route == "signer" else "zark-mail/1"
                result = self.server.transport.exchange(body, protocol)
        except (OSError, ValueError, RecursionError, http.client.HTTPException):
            return self.reply(503, SAFE_ERROR)
        self.reply(200, result)

    def status(self):
        issues, assets_ready, connected = [], False, False
        try:
            self.server.assets.verify()
            assets_ready = True
        except (OSError, ValueError):
            issues.append({"code": "proof_bundle_mismatch", "message": "Pinned proof assets unavailable"})
        try:
            reply = self.server.transport.exchange({"version": 1, "method": "GET", "path": "/health", "body": None},
                                                   "zark-mail/1", timeout=5)
            connected = isinstance(reply, dict) and reply.get("ok") is True
        except (OSError, ValueError):
            pass
        if not connected:
            issues.append({"code": "mailbox_unhealthy", "message": "Pinned mailbox unavailable"})
        # Legacy connected means mailbox health only, never transfer qualification.
        return {"deployment": self.server.pins["name"], "deploymentId": self.server.pins["deployment"],
                "assetsReady": assets_ready, "connected": connected, "issues": issues}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("pins", "inventory", "suite", "signer-certificate", "chain-certificate", "certificate", "private-key"):
        parser.add_argument("--" + name, type=Path, required=True)
    parser.add_argument("--port", type=int, default=7450)
    parser.add_argument("--origin", default="https://zark.lx.dev")
    parser.add_argument("--host", default="zark-signer.lx.dev")
    parser.add_argument("--check-config", action="store_true")
    args = parser.parse_args()
    pins = decode_json(args.pins.read_bytes())
    if (pins["version"] != 10 or pins["owner_limit"] != 8 or pins["signer"]["port"] != 7448
            or pins["chain"]["port"] != 443 or pins["signer"]["server_name"] != "signer.internal"
            or pins["chain"]["server_name"] != "chain.internal"):
        raise ValueError("unsupported native deployment")
    policy = BrowserPolicy([args.origin], [args.host])
    transport = NativeTransport(pins, args.signer_certificate, args.chain_certificate)
    assets = PublicSuite(args.suite, args.inventory, pins)
    context = server_context(args.certificate, args.private_key)
    if args.check_config:
        print(encode_json({"configuration_valid": True, "deployment": pins["deployment"], "suite": pins["suite"],
                           "public_assets": len(assets.hashes)}).decode())
        return
    with Bridge(("127.0.0.1", args.port), transport, assets, pins, policy, context) as server:
        # Swap only the context for future handshakes. Renewal must not kill
        # requests whose native signer operation may already have committed.
        def reload_tls(_signum, _frame):
            try:
                server.tls_context = server_context(args.certificate, args.private_key)
            except (OSError, ValueError, ssl.SSLError):
                print("TLS reload failed; retaining the current context", flush=True)
        signal.signal(signal.SIGHUP, reload_tls)
        server.serve_forever()


if __name__ == "__main__":
    main()
