"""Public, method-limited HTTPS facade for the existing MutinyNet Core node.

This process never serves the Core cookie or an unrestricted Core RPC endpoint.
It also serves only the public proof files named by the checked-in asset list,
and forwards `/faucet` to the optional loopback faucet, which holds its own
restricted wallet credential.
"""

import argparse
import base64
import hashlib
import http.client
import ipaddress
import json
import os
import re
import socket
import ssl
import stat
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from observation import observe, validate_request
from browser_policy import BrowserPolicy


RPC_METHODS = frozenset({
    "getblockchaininfo", "getblockhash", "getrawtransaction", "gettxout",
    "getmempoolentry", "testmempoolaccept", "sendrawtransaction",
    "decoderawtransaction",
})
MAX_RPC_REQUEST = 16 * 1024 * 1024
MAX_RPC_RESPONSE = 32 * 1024 * 1024
MAX_ASSET = 512 * 1024 * 1024
MAX_FAUCET_REQUEST = 4096
MAX_FAUCET_RESPONSE = 64 * 1024
ASSET_NAME = re.compile(r"[A-Za-z0-9_./-]+\Z")


def unique_members(items):
    result = {}
    for key, value in items:
        if key in result:
            raise ValueError("duplicate JSON member")
        result[key] = value
    return result


def public_assets(root: Path, manifest_path: Path):
    manifest = json.loads(manifest_path.read_text())
    if manifest.get("version") != 1 or not isinstance(manifest.get("files"), list):
        raise ValueError("invalid public asset list")
    allowed = {}
    for item in manifest["files"]:
        name = item.get("path")
        expected = item.get("source_sha256", item.get("sha256"))
        if (not isinstance(name, str) or not ASSET_NAME.fullmatch(name)
                or any(part in ("", ".", "..") for part in name.split("/"))
                or not isinstance(expected, str) or not re.fullmatch(r"[0-9a-f]{64}", expected)):
            raise ValueError("invalid public asset entry")
        if name in allowed:
            raise ValueError("duplicate public asset")
        file = root / name
        fd = os.open(file, os.O_RDONLY | os.O_NOFOLLOW)
        try:
            info = os.fstat(fd)
            if not stat.S_ISREG(info.st_mode) or info.st_size > MAX_ASSET:
                raise ValueError("invalid public asset file")
            digest = hashlib.sha256()
            while chunk := os.read(fd, 1024 * 1024):
                digest.update(chunk)
            if digest.hexdigest() != expected:
                raise ValueError("public asset hash mismatch: " + name)
        finally:
            os.close(fd)
        allowed[name] = file
    return allowed


class Gateway(ThreadingHTTPServer):
    daemon_threads = True
    request_queue_size = 32

    def __init__(self, address, assets, rpc_auth, rpc_port, faucet_port=None, *, trusted_proxy=False,
                 allowed_origins=(), allowed_hosts=()):
        if trusted_proxy and not ipaddress.ip_address(address[0]).is_loopback:
            raise ValueError("trusted proxy mode must bind to loopback")
        self.browser_policy = BrowserPolicy(allowed_origins, allowed_hosts)
        super().__init__(address, Handler)
        # Accepted sockets inherit this before TLS begins. Separate TLS records
        # for headers/body (and handshake tickets) must not wait for an ACK.
        self.socket.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        self.trusted_proxy = trusted_proxy
        self.connections = threading.BoundedSemaphore(64)
        self.assets = assets
        self.rpc_auth = rpc_auth
        self.rpc_port = rpc_port
        self.faucet_port = faucet_port
        self.observations = threading.BoundedSemaphore(8)

    def process_request(self, request, client_address):
        if not self.connections.acquire(blocking=False):
            self.shutdown_request(request)
            return
        try:
            super().process_request(request, client_address)
        except BaseException:
            self.connections.release()
            raise

    def process_request_thread(self, request, client_address):
        try:
            super().process_request_thread(request, client_address)
        finally:
            self.connections.release()


class Handler(BaseHTTPRequestHandler):
    disable_nagle_algorithm = True
    # Each idle keep-alive connection holds a thread under TasksMax. Desktop
    # clients close theirs after 30 s, before this limit can race a reuse.
    timeout = 45
    protocol_version = "HTTP/1.1"
    server_version = "ZarkChain/1"
    sys_version = ""

    def log_message(self, format, *args):
        # Do not log transaction bodies or Core error text.
        pass

    def end_headers(self):
        self.send_header("Vary", "Origin, Access-Control-Request-Method, Access-Control-Request-Headers")
        if getattr(self, "cors_origin", None):
            self.send_header("Access-Control-Allow-Origin", self.cors_origin)
            self.send_header("Access-Control-Expose-Headers", "X-Zark-Observation")
        super().end_headers()

    def browser_access(self):
        # Reset on EVERY keep-alive request; a previous caller's allowed origin
        # must never make a subsequent denied response readable.
        self.cors_origin = None
        if self.headers.get_all("Origin") is None:
            return True  # Existing native clients retain their pinned TLS path.
        if (not self.server.browser_policy.allows(self.headers)
                or not (self.path in ("/rpc", "/health") or self.path.startswith("/assets/"))
                or any(self.headers.get_all(name) for name in
                       ("Cookie", "Authorization", "Content-Encoding", "Transfer-Encoding"))):
            self.close_connection = True
            self.error(403, "Browser request denied")
            return False
        self.cors_origin = self.headers["Origin"]
        return True

    def do_OPTIONS(self):
        if not self.browser_access():
            return
        method = "POST" if self.path == "/rpc" else "GET"
        requested = self.headers.get_all("Access-Control-Request-Method", [])
        names = self.headers.get_all("Access-Control-Request-Headers", [])
        lengths = self.headers.get_all("Content-Length", [])
        if (not self.cors_origin or requested != [method] or len(names) > 1
                or any(name.strip().lower() != "content-type" for value in names for name in value.split(","))
                or lengths not in ([], ["0"])):
            self.close_connection = True
            return self.error(400, "Invalid preflight")
        self.send_response(204)
        self.send_header("Content-Length", "0")
        self.send_header("Cache-Control", "no-store")
        self.send_header("Access-Control-Allow-Methods", method)
        self.send_header("Access-Control-Allow-Headers", "Content-Type")
        self.send_header("Access-Control-Max-Age", "60")
        self.end_headers()

    def read_body(self, limit):
        lengths = self.headers.get_all("Content-Length", [])
        if (len(lengths) != 1 or len(lengths[0]) > len(str(limit))
                or not lengths[0].isascii() or not lengths[0].isdecimal()
                or not 0 < int(lengths[0]) <= limit
                or self.headers.get_all("Transfer-Encoding") or self.headers.get_all("Content-Encoding")):
            self.close_connection = True
            self.error(413, "Invalid request size")
            return None
        deadline = time.monotonic() + 8
        body, remaining = bytearray(), int(lengths[0])
        try:
            while remaining:
                timeout = deadline - time.monotonic()
                if timeout <= 0:
                    raise TimeoutError()
                self.connection.settimeout(timeout)
                chunk = self.rfile.read1(min(remaining, 64 * 1024))
                if not chunk:
                    raise OSError("incomplete body")
                body.extend(chunk)
                remaining -= len(chunk)
        except OSError:
            self.close_connection = True
            self.error(408, "Incomplete request")
            return None
        finally:
            self.connection.settimeout(self.timeout)
        return bytes(body)

    def error(self, code, message):
        body = (message + "\n").encode()
        self.send_response(code)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def faucet(self, body=None):
        if self.server.faucet_port is None:
            return self.error(404, "Not found")
        headers = {"Connection": "close"}
        if body is not None:
            # The faucet rate-limits by this address; only the gateway sets it.
            client = self.client_address[0]
            if self.server.trusted_proxy:
                forwarded = self.headers.get_all("X-Zark-Client", [])
                try:
                    if not ipaddress.ip_address(client).is_loopback or len(forwarded) != 1:
                        raise ValueError("invalid proxy source")
                    client = str(ipaddress.ip_address(forwarded[0]))
                except ValueError:
                    return self.error(400, "Invalid proxy client address")
            headers.update({"Content-Type": "application/json", "X-Zark-Client": client})
        try:
            faucet = http.client.HTTPConnection("127.0.0.1", self.server.faucet_port, timeout=30)
            try:
                faucet.request("POST" if body is not None else "GET", "/faucet", body, headers)
                response = faucet.getresponse()
                result = response.read(MAX_FAUCET_RESPONSE + 1)
                status = response.status
            finally:
                faucet.close()
        except (OSError, http.client.HTTPException):
            return self.error(502, "Faucet unavailable")
        if len(result) > MAX_FAUCET_RESPONSE:
            return self.error(502, "Faucet unavailable")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(result)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(result)

    def do_GET(self):
        if not self.browser_access():
            return
        if self.path == "/faucet":
            return self.faucet()
        if self.path == "/health":
            self.send_response(200)
            self.send_header("Content-Length", "0")
            self.send_header("X-Zark-Observation", "1")
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            return
        if not self.path.startswith("/assets/"):
            return self.error(404, "Not found")
        name = self.path[len("/assets/"):]
        file = self.server.assets.get(name)
        if file is None:
            return self.error(404, "Not found")
        try:
            fd = os.open(file, os.O_RDONLY | os.O_NOFOLLOW)
            info = os.fstat(fd)
            if not stat.S_ISREG(info.st_mode) or info.st_size > MAX_ASSET:
                os.close(fd)
                return self.error(404, "Not found")
            self.send_response(200)
            self.send_header("Content-Type", "application/octet-stream")
            self.send_header("Content-Length", str(info.st_size))
            self.send_header("Cache-Control", "public, immutable, max-age=86400")
            self.end_headers()
            with os.fdopen(fd, "rb") as stream:
                while chunk := stream.read(1024 * 1024):
                    self.wfile.write(chunk)
        except (OSError, ConnectionError):
            self.close_connection = True

    def do_POST(self):
        if not self.browser_access():
            return
        if self.cors_origin and self.headers.get_content_type() != "application/json":
            self.close_connection = True
            return self.error(415, "JSON required")
        if self.path == "/faucet":
            body = self.read_body(MAX_FAUCET_REQUEST)
            if body is not None:
                return self.faucet(body)
            return
        if self.path != "/rpc":
            self.close_connection = True
            return self.error(404, "Not found")
        body = self.read_body(MAX_RPC_REQUEST)
        if body is None:
            return
        try:
            # Python keeps the last duplicate member; Core uses the first.
            # Reject ambiguity before authorizing, preserving valid RPC bytes.
            request = json.loads(body, object_pairs_hook=unique_members)
            if (not isinstance(request, dict)
                    or request.get("method") not in RPC_METHODS | {"zark_observe"}
                    or not isinstance(request.get("params", []), list)):
                return self.error(403, "RPC method unavailable")
        except (UnicodeDecodeError, ValueError, TypeError):
            return self.error(400, "Invalid RPC request")
        if request["method"] == "zark_observe":
            return self.observation(request)
        try:
            auth = base64.b64encode(self.server.rpc_auth).decode("ascii")
            core = http.client.HTTPConnection("127.0.0.1", self.server.rpc_port, timeout=10)
            try:
                core.request("POST", "/", body, {
                    "Authorization": "Basic " + auth,
                    "Content-Type": "application/json",
                    "Connection": "close",
                })
                response = core.getresponse()
                result = response.read(MAX_RPC_RESPONSE + 1)
                if len(result) > MAX_RPC_RESPONSE:
                    return self.error(502, "Bitcoin RPC response too large")
                status = response.status
            finally:
                core.close()
        except (OSError, http.client.HTTPException):
            return self.error(502, "Bitcoin RPC unavailable")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(result)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(result)

    def observation(self, request):
        try:
            validate_request(request.get("params"))
            request_id = request.get("id")
            if not (request_id is None or (type(request_id) is int and abs(request_id) < 2**63)
                    or (isinstance(request_id, str) and len(request_id) <= 128)):
                raise ValueError("invalid observation id")
        except (ValueError, TypeError):
            return self.error(400, "Invalid observation request")
        if not self.server.observations.acquire(blocking=False):
            return self.error(503, "Observation capacity unavailable")
        try:
            result = observe(request["params"], self.server.rpc_auth, self.server.rpc_port)
            body = json.dumps({"result": result, "error": None, "id": request.get("id")}).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            self.wfile.write(body)
        except (OSError, ValueError, http.client.HTTPException):
            self.error(502, "Observation unavailable")
        finally:
            self.server.observations.release()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--listen", required=True)
    parser.add_argument("--port", required=True, type=int)
    parser.add_argument("--rpc-port", required=True, type=int)
    parser.add_argument("--assets", required=True, type=Path)
    parser.add_argument("--manifest", required=True, type=Path)
    parser.add_argument("--certificate")
    parser.add_argument("--private-key")
    parser.add_argument("--trusted-loopback-proxy", action="store_true")
    parser.add_argument("--rpc-auth", required=True, type=Path)
    parser.add_argument("--faucet-port", type=int)
    parser.add_argument("--allowed-origin", action="append", default=[])
    parser.add_argument("--allowed-host", action="append", default=[])
    args = parser.parse_args()
    assets = public_assets(args.assets, args.manifest)
    auth = args.rpc_auth.read_bytes().strip()
    if not auth or b":" not in auth or b"\n" in auth:
        raise ValueError("invalid private RPC credential")
    if args.trusted_loopback_proxy:
        if not ipaddress.ip_address(args.listen).is_loopback or args.certificate or args.private_key:
            parser.error("proxy mode requires a loopback address and no TLS files")
    elif not args.certificate or not args.private_key:
        parser.error("direct mode requires certificate and private key")
    server = Gateway((args.listen, args.port), assets, auth, args.rpc_port, args.faucet_port,
                     trusted_proxy=args.trusted_loopback_proxy,
                     allowed_origins=args.allowed_origin, allowed_hosts=args.allowed_host)
    if not args.trusted_loopback_proxy:
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.minimum_version = ssl.TLSVersion.TLSv1_3
        context.set_alpn_protocols(["http/1.1"])
        context.load_cert_chain(args.certificate, args.private_key)
        server.socket = context.wrap_socket(server.socket, server_side=True)
    try:
        server.serve_forever()
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
