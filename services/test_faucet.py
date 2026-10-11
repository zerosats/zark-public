import sys
import tempfile
import unittest
from decimal import Decimal
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
import faucet
from faucet import CoreError, Faucet, Refusal, POOL_LABEL, POOL_OUTPUT_SAT

TAPROOT = "tb1p" + "q" * 58


class FakeCore:
    """Wallet RPC double with Core-style UTXOs, labels, locks and broadcasts."""

    def __init__(self, funding_sat=100_000_000):
        self.utxos, self.locks, self.known = {}, set(), set()
        self.broadcast, self.signed, self.transactions, self.addresses = [], {}, 0, 0
        if funding_sat:
            self.add(funding_sat, "", 6)

    def add(self, amount_sat, label, confirmations):
        self.transactions += 1
        txid = f"{self.transactions:064x}"
        self.utxos[(txid, 0)] = {"txid": txid, "vout": 0, "label": label, "safe": True,
                                 "confirmations": confirmations,
                                 "amount": Decimal(amount_sat) / 100_000_000}
        return txid

    def call(self, method, *params):
        if method == "validateaddress":
            ok = params[0].startswith("tb1p")
            return {"isvalid": ok, "iswitness": ok, "witness_version": 1 if ok else 0,
                    "witness_program": "ab" * 32}
        if method == "listunspent":
            return [u for key, u in self.utxos.items()
                    if key not in self.locks and u["confirmations"] >= params[0]]
        if method == "getnewaddress":
            self.addresses += 1
            return f"tb1ppool{self.addresses}"
        if method == "walletcreatefundedpsbt":
            spent = sum(self.utxos[(i["txid"], i["vout"])]["amount"] for i in params[0])
            paid = sum(Decimal(next(iter(o.values()))) for o in params[1])
            return {"psbt": ("split", params[0], len(params[1]), spent - paid - Decimal("0.0001"))}
        if method == "createpsbt":
            return ("grant", params[0], next(iter(params[1][0])))
        if method == "walletprocesspsbt":
            self.transactions += 1
            raw = f"02{self.transactions:04x}"
            self.signed[raw] = params[0]
            return {"complete": True, "hex": raw}
        if method == "decoderawtransaction":
            kind, inputs, address = self.signed[params[0]]
            return {"txid": f"{int(params[0][2:], 16):064x}",
                    "vin": [dict(i, txinwitness=["00"]) for i in inputs],
                    "vout": [{"value": Decimal("0.00025"), "scriptPubKey": {"address": address}}]}
        if method == "sendrawtransaction":
            kind, inputs, count, change = self.signed[params[0]]
            for i in inputs:
                del self.utxos[(i["txid"], i["vout"])]
            for _ in range(count):
                self.add(POOL_OUTPUT_SAT, POOL_LABEL, 0)
            if change > 0:
                self.add(int(change * 100_000_000), "", 0)
            self.broadcast.append(params[0])
            return "txid"
        if method == "listlockunspent":
            return [{"txid": t, "vout": v} for t, v in self.locks]
        if method == "lockunspent":
            outpoints = {(o["txid"], o["vout"]) for o in params[1]}
            self.locks = self.locks - outpoints if params[0] else self.locks | outpoints
            return True
        if method == "gettransaction":
            if params[0] not in self.known:
                raise CoreError(-5, "Invalid or non-wallet transaction id")
            return {}
        raise AssertionError(method)

    def mine(self):
        for utxo in self.utxos.values():
            utxo["confirmations"] += 1

    def publish(self, raw):
        """The user's wallet broadcasts a grant."""
        kind, inputs, _ = self.signed[raw]
        for i in inputs:
            del self.utxos[(i["txid"], i["vout"])]
            self.locks.discard((i["txid"], i["vout"]))
        self.known.add(f"{int(raw[2:], 16):064x}")


class FaucetTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.now = 1_000_000
        self.core = FakeCore()
        self.faucet = Faucet(self.core, Path(self.temp.name) / "faucet.sqlite3", lambda: self.now)

    def grant(self, address=TAPROOT, client="198.51.100.1"):
        return self.faucet.grant(address, client)["transaction"]

    def test_grant_spends_one_pool_output_without_change_or_broadcast(self):
        raw = self.grant()
        kind, inputs, address = self.core.signed[raw]
        self.assertEqual((kind, address), ("grant", TAPROOT))
        self.assertEqual(len(inputs), 1)
        spent = self.core.utxos[(inputs[0]["txid"], inputs[0]["vout"])]
        self.assertEqual((spent["label"], faucet.sat(spent["amount"])), (POOL_LABEL, POOL_OUTPUT_SAT))
        self.assertEqual(self.core.locks, {(inputs[0]["txid"], 0)})
        # Only the pool split was broadcast; the grant is returned unbroadcast.
        self.assertEqual([self.core.signed[r][0] for r in self.core.broadcast], ["split"])

    def test_one_large_funding_output_does_not_block_other_claims(self):
        first = self.grant("tb1pfirst", "198.51.100.1")
        second = self.grant("tb1psecond", "198.51.100.2")
        self.assertNotEqual(self.core.signed[first][1], self.core.signed[second][1])
        self.assertTrue(self.faucet.status()["available"])

    def test_retry_and_late_resume_return_the_same_still_valid_grant(self):
        raw = self.grant()
        outpoint = self.core.signed[raw][1][0]
        self.now += faucet.RESERVATION_SECONDS + 1
        for n in range(faucet.POOL_REFILL + 5):  # drain and refill the pool
            self.grant(f"tb1pother{n}", f"203.0.{n}.1")
            self.core.mine()
            self.now += faucet.DAY // faucet.DAILY_GRANTS + 1
        self.core.locks.clear()  # e.g. Core wallet reloaded without persistent locks
        self.assertEqual(self.grant(TAPROOT, "192.0.2.9"), raw)
        self.assertIn((outpoint["txid"], outpoint["vout"]), self.core.utxos)
        self.assertIn((outpoint["txid"], outpoint["vout"]), self.core.locks)
        statuses = dict(self.faucet.db.execute("SELECT address, status FROM grants"))
        self.assertEqual(statuses[TAPROOT], "expired")
        self.core.publish(raw)
        self.faucet.settle()
        self.assertEqual(dict(self.faucet.db.execute("SELECT address, status FROM grants"))[TAPROOT], "funded")

    def test_rejects_non_taproot_addresses(self):
        with self.assertRaises(Refusal) as refused:
            self.grant("tb1q" + "q" * 38)
        self.assertEqual((refused.exception.status, refused.exception.code), (400, "invalid_address"))

    def test_client_and_daily_limits(self):
        for n in range(faucet.CLIENT_DAILY_GRANTS):
            self.grant(f"tb1p{n}", "198.51.100.1")
        with self.assertRaises(Refusal) as refused:
            self.grant("tb1pnext", "198.51.100.1")
        self.assertEqual(refused.exception.code, "daily_limit")
        for n in range(faucet.DAILY_GRANTS - faucet.CLIENT_DAILY_GRANTS):
            self.grant(f"tb1pother{n}", f"203.0.113.{n}")
        with self.assertRaises(Refusal):
            self.grant("tb1pfinal", "192.0.2.1")
        self.assertFalse(self.faucet.status()["available"])
        self.now += faucet.DAY + 1
        self.grant("tb1pfinal", "192.0.2.1")

    def test_shared_ip_limits_are_configurable_without_losing_exact_retries(self):
        self.faucet = Faucet(self.core, Path(self.temp.name) / "shared.sqlite3", lambda: self.now,
                             daily_grants=5, client_daily_grants=4)
        first = self.grant("tb1pshared0")
        for n in range(1, 4):
            self.grant(f"tb1pshared{n}")
        with self.assertRaises(Refusal):
            self.grant("tb1ptoomany")
        self.assertEqual(self.grant("tb1pshared0"), first)
        self.grant("tb1plast", "198.51.100.2")
        self.assertFalse(self.faucet.status()["available"])
        for limits in [(0, 0), (5, 6), (10001, 3)]:
            with self.assertRaises(ValueError):
                Faucet(self.core, Path(self.temp.name) / "bad.sqlite3", daily_grants=limits[0],
                       client_daily_grants=limits[1])

    def test_empty_wallet_is_reported(self):
        self.core = FakeCore(funding_sat=0)
        self.faucet = Faucet(self.core, Path(self.temp.name) / "empty.sqlite3", lambda: self.now)
        with self.assertRaises(Refusal) as refused:
            self.grant()
        self.assertEqual((refused.exception.status, refused.exception.code), (503, "empty"))
        self.assertFalse(self.faucet.status()["available"])


if __name__ == "__main__":
    unittest.main()
