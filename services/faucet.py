"""Loopback MutinyNet faucet that sponsors new Zark deposits.

The public gateway forwards `/faucet` here. For each request the faucet signs a
fixed-amount transaction to the wallet's fresh deposit address and returns it
unbroadcast: the Zark wallet must save its recovery before it may publish the
funding, so the faucet never broadcasts a grant.

Each grant spends exactly one dedicated pool output, with no change, and that
output stays persistently locked. A granted transaction therefore remains valid
until its wallet publishes it, however long an interrupted claim takes to
resume, and an unfinished claim never ties up the faucet's other funds. The pool
is refilled from the wallet's remaining balance by a split transaction.
"""

import argparse
import base64
import http.client
import json
import sqlite3
import time
from decimal import Decimal
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path


GRANT_SAT = 25_000
# A one-input, one-output Taproot grant is about 111 vB; this pays ~2.7 sat/vB.
GRANT_FEE_SAT = 300
POOL_OUTPUT_SAT = GRANT_SAT + GRANT_FEE_SAT
POOL_LABEL = "zark-faucet-pool"
POOL_LOW = 10
POOL_REFILL = 40
DAILY_GRANTS = 20
CLIENT_DAILY_GRANTS = 3
# Unbroadcast grants stop counting toward the daily cap after this long. Their
# pool outputs stay locked so the saved claim can still be completed later.
RESERVATION_SECONDS = 24 * 60 * 60
FEE_RATE = 2  # sat/vB for pool refills
DAY = 24 * 60 * 60
MAX_REQUEST = 4096
SCHEMA = """
CREATE TABLE IF NOT EXISTS grants (
    address TEXT PRIMARY KEY,
    client TEXT NOT NULL,
    created INTEGER NOT NULL,
    txid TEXT NOT NULL,
    raw TEXT NOT NULL,
    inputs TEXT NOT NULL,
    status TEXT NOT NULL CHECK (status IN ('reserved', 'funded', 'expired'))
);
"""


def sat(amount):
    return int(Decimal(amount) * 100_000_000)


def btc(amount_sat):
    return str(Decimal(amount_sat) / 100_000_000)


class Refusal(Exception):
    def __init__(self, status, code):
        super().__init__(code)
        self.status, self.code = status, code


class Core:
    """Minimal JSON-RPC client for the faucet's restricted wallet account."""

    def __init__(self, auth: bytes, port: int, wallet: str):
        self.auth = "Basic " + base64.b64encode(auth).decode("ascii")
        self.port, self.path = port, "/wallet/" + wallet

    def call(self, method, *params):
        body = json.dumps({"jsonrpc": "1.0", "id": "faucet", "method": method,
                           "params": list(params)})
        core = http.client.HTTPConnection("127.0.0.1", self.port, timeout=30)
        try:
            core.request("POST", self.path, body, {
                "Authorization": self.auth, "Content-Type": "application/json"})
            reply = json.loads(core.getresponse().read(4 * 1024 * 1024), parse_float=Decimal)
        finally:
            core.close()
        if reply.get("error"):
            raise CoreError(reply["error"].get("code"), reply["error"].get("message", ""))
        return reply["result"]


class CoreError(Exception):
    def __init__(self, code, message):
        super().__init__(message)
        self.code = code


class Faucet:
    def __init__(self, core: Core, database: Path, clock=time.time, *,
                 daily_grants=DAILY_GRANTS, client_daily_grants=CLIENT_DAILY_GRANTS):
        if not (1 <= client_daily_grants <= daily_grants <= 10000):
            raise ValueError("invalid faucet daily limits")
        self.daily_grants, self.client_daily_grants = daily_grants, client_daily_grants
        self.core, self.clock = core, clock
        self.db = sqlite3.connect(database, isolation_level=None)
        self.db.execute("PRAGMA journal_mode=WAL")
        self.db.execute("PRAGMA synchronous=FULL")
        self.db.executescript(SCHEMA)

    def status(self):
        self.settle()
        available = self.remaining() > 0 and bool(self.pool() or self.refill())
        return {"version": 1, "amount_sat": GRANT_SAT, "available": available}

    def remaining(self):
        since = int(self.clock()) - DAY
        (used,) = self.db.execute(
            "SELECT COUNT(*) FROM grants WHERE created > ? AND status != 'expired'",
            (since,)).fetchone()
        return self.daily_grants - used

    def grant(self, address: str, client: str):
        self.settle()
        prior = self.db.execute(
            "SELECT raw FROM grants WHERE address = ?", (address,)).fetchone()
        if prior:
            # Exact retry or late resume: the grant's pool output is never reused.
            return {"version": 1, "transaction": prior[0]}
        self.check_address(address)
        (recent,) = self.db.execute(
            "SELECT COUNT(*) FROM grants WHERE client = ? AND created > ?",
            (client, int(self.clock()) - DAY)).fetchone()
        if recent >= self.client_daily_grants or self.remaining() <= 0:
            raise Refusal(429, "daily_limit")
        pool = self.pool() or (self.refill() and self.pool())
        if not pool:
            raise Refusal(503, "empty")
        raw, txid, inputs = self.sign(address, pool[0])
        # Record before locking so a crash never hands out an unrecorded grant;
        # a recorded but unlocked output is locked again by the next settle().
        self.db.execute(
            "INSERT INTO grants VALUES (?, ?, ?, ?, ?, ?, 'reserved')",
            (address, client, int(self.clock()), txid, raw, json.dumps(inputs)))
        self.lock(inputs)
        if len(pool) - 1 < POOL_LOW:
            try:
                self.refill()
            except (OSError, CoreError, Refusal, http.client.HTTPException):
                pass  # The grant is already committed; refill on a later request.
        return {"version": 1, "transaction": raw}

    def check_address(self, address):
        info = self.core.call("validateaddress", address)
        if not (info.get("isvalid") and info.get("iswitness")
                and info.get("witness_version") == 1
                and len(info.get("witness_program", "")) == 64):
            raise Refusal(400, "invalid_address")

    def pool(self):
        """Unlocked pool outputs, including our own unconfirmed refills."""
        return sorted((u for u in self.core.call("listunspent", 0)
                       if u.get("label") == POOL_LABEL and u.get("safe")
                       and sat(u["amount"]) == POOL_OUTPUT_SAT),
                      key=lambda u: -u["confirmations"])

    def refill(self):
        """Split confirmed non-pool funds into dedicated grant outputs."""
        sources = [u for u in self.core.call("listunspent", 1)
                   if u.get("label") != POOL_LABEL and u.get("safe")]
        spare = sum(sat(u["amount"]) for u in sources) - 10_000  # fee headroom
        count = min(POOL_REFILL, max(spare, 0) // POOL_OUTPUT_SAT)
        if count == 0:
            return False
        outputs = [{self.core.call("getnewaddress", POOL_LABEL, "bech32m"): btc(POOL_OUTPUT_SAT)}
                   for _ in range(count)]
        funded = self.core.call(
            "walletcreatefundedpsbt",
            [{"txid": u["txid"], "vout": u["vout"]} for u in sources], outputs, 0,
            {"add_inputs": False, "fee_rate": FEE_RATE, "change_type": "bech32m"})
        signed = self.core.call("walletprocesspsbt", funded["psbt"], True, "DEFAULT", False, True)
        if not signed.get("complete") or not signed.get("hex"):
            raise Refusal(503, "unavailable")
        self.core.call("sendrawtransaction", signed["hex"])
        return True

    def sign(self, address, output):
        outpoint = {"txid": output["txid"], "vout": output["vout"]}
        psbt = self.core.call("createpsbt", [outpoint], [{address: btc(GRANT_SAT)}], 0, False)
        signed = self.core.call("walletprocesspsbt", psbt, True, "DEFAULT", False, True)
        if not signed.get("complete") or not signed.get("hex"):
            raise Refusal(503, "unavailable")
        decoded = self.core.call("decoderawtransaction", signed["hex"])
        # The wallet requires native-witness inputs and exactly one grant output.
        if (len(decoded["vin"]) != 1 or len(decoded["vout"]) != 1
                or decoded["vout"][0]["scriptPubKey"].get("address") != address
                or sat(decoded["vout"][0]["value"]) != GRANT_SAT
                or decoded["vin"][0].get("scriptSig", {}).get("hex")
                or not decoded["vin"][0].get("txinwitness")):
            raise Refusal(503, "unavailable")
        return signed["hex"], decoded["txid"], [outpoint]

    def locked(self):
        return {(o["txid"], o["vout"]) for o in self.core.call("listlockunspent")}

    def lock(self, inputs):
        held = self.locked()
        missing = [i for i in inputs if (i["txid"], i["vout"]) not in held]
        if missing:
            self.core.call("lockunspent", False, missing, True)

    def unlock(self, inputs):
        held = self.locked()
        present = [i for i in inputs if (i["txid"], i["vout"]) in held]
        if present:
            self.core.call("lockunspent", True, present)

    def seen(self, txid):
        try:
            self.core.call("gettransaction", txid)
            return True
        except CoreError as error:
            if error.code == -5:
                return False
            raise

    def settle(self):
        """Mark broadcast grants funded and keep every other grant's output locked."""
        cutoff = int(self.clock()) - RESERVATION_SECONDS
        rows = self.db.execute(
            "SELECT address, txid, inputs, created, status FROM grants"
            " WHERE status IN ('reserved', 'expired')").fetchall()
        for address, txid, inputs, created, status in rows:
            inputs = json.loads(inputs)
            if self.seen(txid):
                self.unlock(inputs)
                self.db.execute("UPDATE grants SET status = 'funded' WHERE address = ?", (address,))
                continue
            self.lock(inputs)
            if status == "reserved" and created <= cutoff:
                self.db.execute("UPDATE grants SET status = 'expired' WHERE address = ?", (address,))


class Server(HTTPServer):
    # Single-threaded on purpose: coin selection, locking and the ledger must
    # not interleave between concurrent grants.
    request_queue_size = 16

    def __init__(self, address, faucet):
        super().__init__(address, Handler)
        self.faucet = faucet


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    server_version = "ZarkFaucet/1"
    sys_version = ""
    timeout = 30

    def log_message(self, format, *args):
        pass

    def reply(self, status, value):
        body = json.dumps(value).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def handle_faucet(self, operation):
        if self.path != "/faucet":
            return self.reply(404, {"error": "not_found"})
        try:
            return self.reply(200, operation())
        except Refusal as refusal:
            return self.reply(refusal.status, {"error": refusal.code})
        except (OSError, CoreError, http.client.HTTPException, ValueError, KeyError):
            return self.reply(503, {"error": "unavailable"})

    def do_GET(self):
        self.handle_faucet(self.server.faucet.status)

    def do_POST(self):
        length = self.headers.get("Content-Length", "")
        client = self.headers.get("X-Zark-Client", "")
        if not length.isdecimal() or not 0 < int(length) <= MAX_REQUEST or not client:
            self.close_connection = True
            return self.reply(400, {"error": "invalid_request"})
        try:
            request = json.loads(self.rfile.read(int(length)))
            if not isinstance(request, dict) or set(request) != {"address"}:
                raise ValueError
            address = request["address"]
            if not isinstance(address, str) or not 0 < len(address) <= 128:
                raise ValueError
        except (ValueError, UnicodeDecodeError):
            return self.reply(400, {"error": "invalid_request"})
        self.handle_faucet(lambda: self.server.faucet.grant(address, client))


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--port", required=True, type=int)
    parser.add_argument("--rpc-port", required=True, type=int)
    parser.add_argument("--rpc-auth", required=True, type=Path)
    parser.add_argument("--wallet", default="zark-faucet")
    parser.add_argument("--database", required=True, type=Path)
    parser.add_argument("--daily-grants", type=int, default=DAILY_GRANTS)
    parser.add_argument("--client-daily-grants", type=int, default=CLIENT_DAILY_GRANTS)
    args = parser.parse_args()
    auth = args.rpc_auth.read_bytes().strip()
    if not auth or b":" not in auth or b"\n" in auth:
        raise ValueError("invalid faucet RPC credential")
    server = Server(("127.0.0.1", args.port), Faucet(Core(auth, args.rpc_port, args.wallet), args.database,
                    daily_grants=args.daily_grants, client_daily_grants=args.client_daily_grants))
    try:
        server.serve_forever()
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
