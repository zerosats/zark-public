"""Pinned native transports for the browser adapter; never retry a sent call."""
import hashlib
import http.client
import json
import re
import socket
import ssl
import time
from pathlib import Path

LIMIT = 3_000_000


def decode_json(raw):
    def pairs(items):
        result = {}
        for key, value in items:
            if key in result:
                raise ValueError("duplicate JSON member")
            result[key] = value
        return result

    def invalid(_):
        raise ValueError("invalid JSON constant")

    return json.loads(raw.decode("utf-8"), object_pairs_hook=pairs, parse_constant=invalid)


def encode_json(value):
    return json.dumps(value, separators=(",", ":"), ensure_ascii=False, allow_nan=False).encode("utf-8")


def chain_params(method, args):
    if not isinstance(method, str) or not isinstance(args, list) or not all(isinstance(v, str) for v in args):
        raise ValueError("invalid chain call")
    if method == "zark_observe":
        if (len(args) != 5 or args[0] != "1" or args[2] != "0"
                or any(not re.fullmatch(r"[a-f0-9]{64}", args[i]) or set(args[i]) == {"0"} for i in (1, 3))
                or not re.fullmatch(r"0|[1-9][0-9]{0,9}", args[4]) or int(args[4]) > 0xffffffff):
            raise ValueError("invalid observation")
        return args[:]
    arities = {"getblockchaininfo": (0,), "getblockhash": (1,), "getrawtransaction": (1, 2, 3),
               "gettxout": (2, 3), "getmempoolentry": (1,), "testmempoolaccept": (1,), "sendrawtransaction": (1,)}
    if len(args) not in arities.get(method, ()):
        raise ValueError("chain method unavailable")
    result = args[:]
    if method in ("getblockhash", "gettxout"):
        index = 0 if method == "getblockhash" else 1
        if not re.fullmatch(r"0|[1-9][0-9]{0,9}", args[index]):
            raise ValueError("invalid chain number")
        result[index] = int(args[index])
    for index in ((1,) if method == "getrawtransaction" else (2,) if method == "gettxout" else ()):
        if index < len(args):
            if args[index] not in ("true", "false"):
                raise ValueError("invalid chain boolean")
            result[index] = args[index] == "true"
    if method == "sendrawtransaction":
        if not re.fullmatch(r"(?:[0-9a-f]{2}){1,100000}", args[0]):
            raise ValueError("invalid signed transaction")
    if method == "testmempoolaccept":
        raws = decode_json(args[0].encode())
        if not isinstance(raws, list) or len(raws) != 1 or not isinstance(raws[0], str) or not re.fullmatch(r"[0-9a-f]+", raws[0]):
            raise ValueError("invalid transaction check")
        result[0] = raws
    return result


def validate_call(route, body):
    if not isinstance(body, dict):
        raise ValueError("invalid envelope")
    if route == "status":
        if body:
            raise ValueError("invalid status call")
    elif route == "signer":
        if set(body) != {"method", "request"} or body["method"] != "zark_request" or not isinstance(body["request"], str):
            raise ValueError("invalid signer call")
    elif route == "mail":
        if (set(body) - {"version", "method", "path", "body", "bearer"}
                or type(body.get("version")) is not int or body["version"] != 1
                or body.get("method") not in ("GET", "POST", "DELETE")
                or not isinstance(body.get("path"), str)
                or not re.fullmatch(r"/(health|v1/offers|v1/mailboxes(?:/[a-f0-9]{64}(?:/messages(?:/[a-f0-9]{64})?)?)?)", body["path"])
                or (body["path"] == "/v1/offers" and body["method"] != "GET")):
            raise ValueError("invalid mailbox call")
    elif route == "faucet":
        if body != {"method": "GET"} and not (set(body) == {"method", "address"}
                and body["method"] == "POST" and isinstance(body["address"], str)
                and re.fullmatch(r"tb1p[a-z0-9]{58}", body["address"])):
            raise ValueError("invalid faucet call")
    elif route == "chain":
        if set(body) != {"method", "args"}:
            raise ValueError("invalid chain call")
        chain_params(body["method"], body["args"])
    else:
        raise ValueError("unknown route")


class NativeTransport:
    def __init__(self, pins, signer_certificate, chain_certificate, signer_host="127.0.0.1", chain_host="127.0.0.1"):
        self.pins = pins
        self.hosts = {"signer": signer_host, "chain": chain_host}
        self.contexts = {}
        for target, filename in (("signer", signer_certificate), ("chain", chain_certificate)):
            pem = Path(filename).read_text("ascii")
            expected = pins["certificate_sha256"] if target == "signer" else pins["chain"]["certificate_sha256"]
            if hashlib.sha256(ssl.PEM_cert_to_DER_cert(pem)).hexdigest() != expected:
                raise ValueError(target + " certificate pin mismatch")
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            context.load_verify_locations(cadata=pem)
            context.minimum_version = ssl.TLSVersion.TLSv1_3 if target == "signer" else ssl.TLSVersion.TLSv1_2
            self.contexts[target] = context
        # Separate contexts avoid concurrent ALPN policy mutation.
        self.mail_context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        self.mail_context.load_verify_locations(cafile=str(signer_certificate))
        self.mail_context.minimum_version = self.mail_context.maximum_version = ssl.TLSVersion.TLSv1_3
        self.mail_context.set_alpn_protocols(["zark-mail/1"])
        self.contexts["signer"].maximum_version = ssl.TLSVersion.TLSv1_3
        self.contexts["signer"].set_alpn_protocols(["statechain/10"])

    def connect(self, target, protocol=None):
        endpoint = self.pins[target]
        context = self.mail_context if protocol == "zark-mail/1" else self.contexts[target]
        raw = socket.create_connection((self.hosts[target], endpoint["port"]), timeout=5)
        try:
            secure = context.wrap_socket(raw, server_hostname=endpoint["server_name"])
            expected = self.pins["certificate_sha256"] if target == "signer" else endpoint["certificate_sha256"]
            if (hashlib.sha256(secure.getpeercert(binary_form=True)).hexdigest() != expected
                    or (protocol and secure.selected_alpn_protocol() != protocol)):
                secure.close()
                raise ssl.SSLError("pinned TLS authentication failed")
            return secure
        except BaseException:
            raw.close()
            raise

    def exchange(self, body, protocol, timeout=180):
        payload = encode_json(body) + b"\n"
        if len(payload) > LIMIT:
            raise ValueError("native request limit")
        with self.connect("signer", protocol) as connection:
            deadline = time.monotonic() + timeout
            connection.settimeout(timeout)
            # No retries after this write: a lost response can follow a commit.
            connection.sendall(payload)
            chunks = bytearray()
            while True:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise TimeoutError("native response timeout")
                connection.settimeout(remaining)
                chunk = connection.recv(min(65536, LIMIT + 1 - len(chunks)))
                if not chunk:
                    raise OSError("incomplete native response")
                chunks.extend(chunk)
                if len(chunks) > LIMIT:
                    raise OSError("native response limit")
                if b"\n" in chunks:
                    if chunks.index(10) != len(chunks) - 1:
                        raise OSError("native response framing")
                    return decode_json(bytes(chunks))

    def chain_request(self, path, body=None, limit=32 * 1024 * 1024):
        endpoint = self.pins["chain"]
        connection = http.client.HTTPSConnection(endpoint["server_name"], endpoint["port"], timeout=10,
                                                  context=self.contexts["chain"])
        try:
            # Authenticate the peer before any HTTP bytes are transmitted.
            secure = self.connect("chain")
            connection.sock = secure
            secure.settimeout(10)
            payload = encode_json(body) if body is not None else None
            connection.request("POST" if payload is not None else "GET", path, payload,
                               {"Content-Type": "application/json", "Connection": "close"})
            deadline = time.monotonic() + 10
            response = connection.getresponse()
            chunks = bytearray()
            while True:
                if response.isclosed():
                    break
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise TimeoutError("chain response timeout")
                secure.settimeout(remaining)
                chunk = response.read1(min(65536, limit + 1 - len(chunks)))
                if not chunk:
                    if response.length not in (None, 0):
                        raise OSError("incomplete chain response")
                    break
                chunks.extend(chunk)
                if len(chunks) > limit:
                    raise OSError("chain response limit")
            if response.status != 200:
                raise OSError("chain query failed")
            return bytes(chunks), response.getheader("X-Zark-Observation")
        finally:
            connection.close()

    def chain_call(self, body):
        params = chain_params(body["method"], body["args"])
        raw, _ = self.chain_request("/rpc", {"jsonrpc": "2.0", "id": "browser-demo", "method": body["method"], "params": params})
        reply = decode_json(raw)
        if not isinstance(reply, dict) or reply.get("error") or "result" not in reply:
            raise OSError("chain query failed")
        result = reply["result"]
        if body["method"] == "getblockchaininfo":
            if not isinstance(result, dict):
                raise OSError("invalid chain information")
            result.pop("zark_observation_version", None)
            try:
                _, advertised = self.chain_request("/health", limit=4096)
                if advertised == "1":
                    result["zark_observation_version"] = 1
            except (OSError, ValueError, http.client.HTTPException):
                pass  # Optional capability discovery cannot replace chain evidence.
        return result
