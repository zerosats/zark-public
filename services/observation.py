"""Bounded read-only evidence collection. Policy validation remains in the wallet."""
import base64
import http.client
import json
import re
import time

MAX_EVIDENCE = 4_000_000


def validate_request(params):
    if (not isinstance(params, list) or len(params) != 5 or params[0] != "1"
            or any(not isinstance(v, str) for v in params)
            or any(not re.fullmatch(r"[0-9a-f]{64}", params[i]) or params[i] == "0" * 64
                   for i in (1, 3))
            or params[2] != "0"
            or not re.fullmatch(r"0|[1-9][0-9]{0,9}", params[4])
            or int(params[4]) > 0xffffffff):
        raise ValueError("invalid observation request")


def collect(params, rpc):
    validate_request(params)
    reads = []

    def read(method, args):
        try:
            value = rpc(method, args)
            reads.append({"method": method, "args": args, "result": value, "failed": False})
            return value
        except (OSError, ValueError, http.client.HTTPException):
            # Preserve a failed read and still fence the observation. Never
            # forward Core error text, and never convert failure into null.
            reads.append({"method": method, "args": args, "result": None, "failed": True})
            return None

    before = read("getblockchaininfo", [])
    read("getblockhash", ["0"])
    deposit = read("getrawtransaction", [params[3], "true"])
    if isinstance(before, dict) and isinstance(deposit, dict):
        tip, confirmations = before.get("blocks"), deposit.get("confirmations")
        if (type(tip) is int and type(confirmations) is int
                and 0 < confirmations <= tip + 1):
            read("getblockhash", [str(tip + 1 - confirmations)])
    active = read("gettxout", [params[1], params[2], "true"])
    if active is None:
        read("gettxout", [params[3], params[4], "true"])
    # This read must follow ALL evidence, including failures. Stable block tips
    # do not imply a stable mempool; gettxout always includes the mempool.
    read("getblockchaininfo", [])
    return {"version": 1, "request": params, "reads": reads}


def observe(params, auth, port):
    deadline = time.monotonic() + 8
    remaining_bytes = MAX_EVIDENCE - 8192

    def rpc(method, args):
        nonlocal remaining_bytes
        remaining = deadline - time.monotonic()
        if remaining <= 0 or remaining_bytes <= 0:
            raise ValueError("observation budget exhausted")
        converted = list(args)
        if method == "getblockhash":
            converted[0] = int(args[0])
        elif method == "getrawtransaction":
            converted[1] = True
        elif method == "gettxout":
            converted[1], converted[2] = int(args[1]), True
        core = http.client.HTTPConnection("127.0.0.1", port, timeout=remaining)
        try:
            core.request("POST", "/", json.dumps({"id": 1, "method": method, "params": converted}), {
                "Authorization": "Basic " + base64.b64encode(auth).decode("ascii"),
                "Content-Type": "application/json", "Connection": "close"})
            response = core.getresponse()
            body = response.read(remaining_bytes + 1)
            remaining_bytes -= len(body)
            if remaining_bytes < 0 or response.status != 200:
                raise ValueError("Core observation failed")
            reply = json.loads(body)
            if not isinstance(reply, dict) or reply.get("error") is not None or "result" not in reply:
                raise ValueError("Core observation failed")
            return reply["result"]
        finally:
            core.close()

    result = collect(params, rpc)
    if len(json.dumps(result).encode()) > MAX_EVIDENCE - 1024:
        raise ValueError("observation response too large")
    return result
