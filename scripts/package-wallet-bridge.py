"""Build an explicit public-only bridge package from the wallet's trusted pins."""
import argparse
import hashlib
import shutil
import sys
import tarfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "services"))
from wallet_assets import PublicSuite
from wallet_transport import NativeTransport, decode_json


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--wallet", type=Path, required=True)
    args = parser.parse_args()
    pins_path = args.wallet / "browser-core/demo-pins.json"
    inventory = args.wallet / "browser-core/demo-assets.json"
    pins = decode_json(pins_path.read_bytes())
    assets = PublicSuite(args.wallet / "demo-assets/suite", inventory, pins)
    signer_cert = args.wallet / "demo-assets/certificate.pem"
    chain_cert = args.wallet / "server/preview-chain-certificate.pem"
    NativeTransport(pins, signer_cert, chain_cert)  # Checks public certificate pins; opens no connection.
    output = ROOT / "work/wallet-bridge-deploy"
    stage = output / "zark-wallet-bridge"
    stage.mkdir(parents=True, exist_ok=True)
    files = {
        "pins.json": pins_path, "inventory.json": inventory,
        "signer-certificate.pem": signer_cert, "chain-certificate.pem": chain_cert,
    }
    for name in ("browser_policy.py", "wallet_assets.py", "wallet_transport.py", "wallet_bridge.py", "wallet_faucet.py", "test_wallet_bridge.py",
                 "wallet-bridge.nginx.conf", "zark-wallet-bridge.service", "wallet-bridge-run.sh", "wallet-bridge-tls-reload.sh"):
        files["services/" + name] = ROOT / "services" / name
    for name in ("install-wallet-bridge.sh", "check-wallet-bridge.py"):
        files["scripts/" + name] = ROOT / "scripts" / name
    for name in assets.hashes:
        files[name] = args.wallet / "demo-assets" / name
    for name, source in files.items():
        destination = stage / name
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(source, destination)
    archive = output / "zark-wallet-bridge.tar.gz"
    with tarfile.open(archive, "w:gz") as bundle:
        for name in sorted(files):
            bundle.add(stage / name, arcname="zark-wallet-bridge/" + name, recursive=False)
    print(archive)
    print("sha256=" + hashlib.sha256(archive.read_bytes()).hexdigest())
    print("public_assets=" + str(len(assets.hashes)))


if __name__ == "__main__":
    main()
