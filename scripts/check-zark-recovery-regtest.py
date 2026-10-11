#!/usr/bin/env python3
"""Native receiver recovery/portable backup against a new isolated Core regtest.

Creates only work/zark-regtest-<random>, launches one owned foreground node,
and stops only that child. No existing wallet/node/home is accessed. No proofs,
signer process, real network, or transferable funds are involved. Keeps an audit.
"""
import datetime
import json
import os
from pathlib import Path
import shutil
import socket
import subprocess
import tempfile
import time

ROOT = Path(__file__).resolve().parents[1]
BITCOIND = Path(os.environ.get("ZARK_BITCOIND", shutil.which("bitcoind") or "bitcoind")).resolve()
CLI = Path(os.environ.get("ZARK_BITCOIN_CLI", shutil.which("bitcoin-cli") or "bitcoin-cli")).resolve()
TOOLCHAIN = Path(subprocess.check_output(["rustup", "which", "--toolchain", "1.95.0", "cargo"], text=True).strip()).parent


def write(path, value):
    data = json.dumps(value, sort_keys=True, indent=2).encode() + b"\n"
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "wb") as output:
        output.write(data)
        output.flush()
        os.fsync(output.fileno())


def read(path):
    return json.loads(path.read_text())


def free_port():
    with socket.socket() as reservation:
        reservation.bind(("127.0.0.1", 0))
        return reservation.getsockname()[1]


class Test:
    def __init__(self):
        os.umask(0o077)
        (ROOT / "work").mkdir(exist_ok=True)
        self.home = Path(tempfile.mkdtemp(prefix="zark-regtest-", dir=ROOT / "work"))
        self.node = self.home / "node"
        self.node.mkdir(mode=0o700)
        self.wallets = self.node / "wallets"
        self.wallets.mkdir(mode=0o700)
        self.config = self.node / "bitcoin.conf"
        self.config.touch(mode=0o600)
        self.cookie = self.node / "regtest/.cookie"
        self.port = free_port()
        self.child = None
        self.audit = {"schema": "zark-native-recovery-regtest-audit", "version": 1,
                      "started_utc": datetime.datetime.now(datetime.timezone.utc).isoformat(),
                      "home": str(self.home), "rpc_port": self.port,
                      "real_proofs": False, "signer_used": False,
                      "chain": "regtest", "p2p_enabled": False, "steps": []}
        write(self.home / "run.json", {"schema": "zark-regtest-test-run", "version": 1})

    def command(self, command, timeout=60):
        process = subprocess.run([str(p) for p in command], stdin=subprocess.DEVNULL,
                                 capture_output=True, text=True, timeout=timeout)
        if process.returncode:
            raise RuntimeError(f"test command failed ({command[0]}): {process.stderr[-2000:]}")
        return process.stdout.strip()

    def rpc(self, method, *args, wallet=False):
        command = [CLI, "-regtest", f"-conf={self.config}", f"-datadir={self.node}",
                   f"-rpccookiefile={self.cookie}", "-rpcconnect=127.0.0.1",
                   f"-rpcport={self.port}", "-rpcclienttimeout=10"]
        if wallet:
            command.append("-rpcwallet=faucet")
        command.extend([method, *(arg if isinstance(arg, str) else json.dumps(arg) for arg in args)])
        output = self.command(command, timeout=20)
        try:
            return json.loads(output)
        except json.JSONDecodeError:
            return output

    def adapter(self, phase):
        env = dict(os.environ)
        env.update({"PATH": str(TOOLCHAIN) + os.pathsep + env.get("PATH", ""),
                    "RUSTC": str(TOOLCHAIN / "rustc"),
                    "CARGO_TARGET_DIR": str(ROOT / "work/implementation-target"),
                    "ZARK_REGTEST_HOME": str(self.home), "ZARK_REGTEST_PHASE": phase})
        if (ROOT / "work/cargo/registry").is_dir():
            env["CARGO_HOME"] = str(ROOT / "work/cargo")
        # Keep the pinned toolchain, and never import caller Rust overrides.
        env.pop("RUSTFLAGS", None)
        env.pop("CARGO_ENCODED_RUSTFLAGS", None)
        args = [TOOLCHAIN / "cargo", "test", "-p", "zark-wallet",
                "--test", "zark_recovery_regtest", "zark_regtest_adapter", "--locked", "--offline",
                "--", "--ignored", "--exact", "--test-threads=1"]
        with (self.home / f"adapter-{phase}.log").open("xb") as log:
            process = subprocess.run([str(p) for p in args], cwd=ROOT, env=env,
                                     stdin=subprocess.DEVNULL, stdout=log, stderr=log, timeout=600)
        if process.returncode:
            raise RuntimeError(f"native adapter {phase} failed; see adapter-{phase}.log")

    def admission(self, label, transaction, allowed, reason=None):
        tip = self.rpc("getblockcount")
        result = self.rpc("testmempoolaccept", [transaction])[0]
        self.audit["steps"].append({"label": label, "tip": tip,
                                    "candidate_height": tip + 1, "admission": result})
        assert result["allowed"] is allowed, (label, result)
        if reason:
            assert result.get("reject-reason") == reason, (label, result)
        return tip

    def mine_to(self, height):
        current = self.rpc("getblockcount")
        assert current <= height
        if current < height:
            self.rpc("generatetoaddress", height - current, self.mining_address)
        assert self.rpc("getblockcount") == height

    def execute(self):
        for binary in [BITCOIND, CLI, TOOLCHAIN / "cargo", TOOLCHAIN / "rustc"]:
            assert binary.is_file(), f"Required installed tool missing: {binary}"
        self.audit["bitcoind_version"] = self.command([BITCOIND, "--version"]).splitlines()[0]
        self.audit["bitcoin_cli_version"] = self.command([CLI, "--version"]).splitlines()[0]
        self.audit["rustc_version"] = self.command([TOOLCHAIN / "rustc", "--version"])
        assert self.audit["rustc_version"].startswith("rustc 1.95.0 ")
        help_text = self.command([BITCOIND, "-help"])
        for flag in ["-rpcbind=", "-rpcallowip=", "-listen", "-connect=", "-networkactive"]:
            assert flag in help_text
        args = [BITCOIND, "-regtest", f"-conf={self.config}", f"-datadir={self.node}",
                f"-walletdir={self.wallets}", f"-rpccookiefile={self.cookie}",
                f"-rpcport={self.port}", "-rpcbind=127.0.0.1", "-rpcallowip=127.0.0.1",
                "-server=1", "-daemon=0", "-listen=0", "-connect=0", "-networkactive=0",
                "-discover=0", "-dnsseed=0", "-fixedseeds=0", "-listenonion=0", "-natpmp=0",
                "-txindex=1", "-nosettings", "-fallbackfee=0.00001", "-dbcache=32",
                "-maxmempool=20", "-printtoconsole=1", "-nodebuglogfile"]
        self.audit["node_command"] = [str(p) for p in args]
        with (self.home / "node.log").open("xb") as log:
            self.child = subprocess.Popen([str(p) for p in args], stdin=subprocess.DEVNULL,
                                          stdout=log, stderr=log, start_new_session=True)
        self.audit["owned_node_pid"] = self.child.pid
        for _ in range(100):
            assert self.child.poll() is None, "Owned regtest node exited; see node.log"
            try:
                if self.rpc("getblockcount") == 0:
                    break
            except RuntimeError:
                time.sleep(0.1)
        else:
            raise RuntimeError("Owned regtest RPC did not start")
        assert self.rpc("getblockchaininfo")["chain"] == "regtest"
        network = self.rpc("getnetworkinfo")
        assert network["networkactive"] is False and network["connections"] == 0
        write(self.home / "core-rpc-help.json", {method: self.rpc("help", method) for method in
              ["createwallet", "sendtoaddress", "generatetoaddress", "testmempoolaccept", "sendrawtransaction"]})
        self.rpc("createwallet", "faucet")
        self.mining_address = self.rpc("getnewaddress", wallet=True)
        self.rpc("generatetoaddress", 101, self.mining_address)
        self.adapter("prepare")
        prepared = read(self.home / "prepared.json")
        funding_txid = self.rpc("sendtoaddress", prepared["funding_address"], "0.00100000", wallet=True)
        funding = self.rpc("getrawtransaction", funding_txid, True)
        outputs = [v for v in funding["vout"] if v["scriptPubKey"].get("address") == prepared["funding_address"]]
        assert len(outputs) == 1 and outputs[0]["value"] == 0.001
        self.rpc("generatetoaddress", 1, self.mining_address)
        write(self.home / "funding.json", {"txid": funding_txid, "vout": outputs[0]["n"],
                                          "amount": 100000, "transaction": funding["hex"]})
        self.audit["funding_transaction"] = funding_txid
        self.adapter("build")
        transactions = read(self.home / "transactions.json")
        self.admission("unpublished_activation", transactions["recovery"], False, "missing-inputs")
        assert self.rpc("sendrawtransaction", transactions["activation"]) == transactions["activation_txid"]
        self.rpc("generatetoaddress", 1, self.mining_address)
        height = self.rpc("getblockcount")
        activation = self.rpc("getrawtransaction", transactions["activation_txid"], True)
        assert activation["confirmations"] == 1
        observations = [{"label": "activation_confirmed", "height": height}]
        self.mine_to(height + 6)
        before = self.admission("one_candidate_block_before_maturity", transactions["recovery"], False, "non-BIP68-final")
        observations.append({"label": "before_boundary", "height": before})
        self.mine_to(height + 7)
        eligible = self.admission("first_eligible_candidate_block", transactions["recovery"], True)
        observations.append({"label": "first_eligible", "height": eligible})
        self.admission("predecessor_delay_still_immature", transactions["old_delay_comparator"], False, "non-BIP68-final")
        assert self.rpc("sendrawtransaction", transactions["recovery"]) == transactions["recovery_txid"]
        self.rpc("generatetoaddress", 1, self.mining_address)
        assert self.rpc("getblockcount") == height + 8
        confirmed = self.rpc("getrawtransaction", transactions["recovery_txid"], True)
        assert confirmed["confirmations"] == 1
        self.audit.update({"activation_height": height, "recovery_first_confirmation_height": height + 8,
                           "activation_txid": transactions["activation_txid"], "recovery_txid": transactions["recovery_txid"]})
        # A copied archive is the only private receiver file used from here on.
        portable = self.home / "portable"
        portable.mkdir(mode=0o700)
        shutil.copy2(self.home / "source/recovery.json", portable / "recovery.json")
        (self.home / "source").rename(self.home / "source-unavailable")
        self.adapter("payout")
        payout = read(self.home / "payout.json")
        self.admission("portable_archive_payout_spend", payout["transaction"], True)
        assert self.rpc("sendrawtransaction", payout["transaction"]) == payout["txid"]
        self.rpc("generatetoaddress", 1, self.mining_address)
        assert self.rpc("gettxout", payout["txid"], 0)["value"] == 0.00097
        self.mine_to(height + 11)
        observations.append({"label": "expired_margin_fresh_tip", "height": self.rpc("getblockcount")})
        observations.append({"label": "stale_tip_would_appear_safe", "height": eligible})
        write(self.home / "observations.json", {"activation_height": height, "tips": observations})
        self.adapter("windows")
        windows = read(self.home / "windows.json")
        indexed = {item["label"]: item for item in windows["observations"]}
        assert indexed["first_eligible"]["next_maturity"] == height + 8
        assert indexed["first_eligible"]["previous_maturity"] == height + 12
        assert indexed["first_eligible"]["earliest_next_confirmation"] == height + 8
        assert indexed["expired_margin_fresh_tip"]["accepted"] is False
        assert indexed["stale_tip_would_appear_safe"]["accepted"] is True
        assert windows["wrong_decrement_rejected"] and windows["time_flag_rejected"]
        self.audit["native_timing_windows"] = windows
        self.audit["portable_only_payout_txid"] = payout["txid"]
        self.audit["passed"] = True

    def close(self):
        if self.child is not None:
            if self.child.poll() is None:
                try:
                    self.rpc("stop")
                    self.child.wait(timeout=20)
                except (RuntimeError, subprocess.TimeoutExpired):
                    # The Popen child is our own process; never use pkill or a
                    # PID read from unrelated state. Preserve the test data.
                    self.child.terminate()
                    try:
                        self.child.wait(timeout=10)
                    except subprocess.TimeoutExpired:
                        self.child.kill()
                        self.child.wait(timeout=10)
            self.audit["owned_node_stopped"] = self.child.poll() is not None
            self.audit["owned_node_exit_code"] = self.child.returncode
        self.audit["finished_utc"] = datetime.datetime.now(datetime.timezone.utc).isoformat()
        write(self.home / "audit.json", self.audit)


if __name__ == "__main__":
    test = Test()
    print(f"Isolated regtest run: {test.home}", flush=True)
    try:
        test.execute()
    except Exception as error:
        test.audit["passed"] = False
        test.audit["error"] = str(error)
        raise
    finally:
        test.close()
    print(f"PASS: {test.home / 'audit.json'}", flush=True)
