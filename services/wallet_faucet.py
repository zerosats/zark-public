"""Narrow loopback faucet adapter. Returns a signed transaction, never broadcasts."""
import http.client
import re
from wallet_transport import decode_json, encode_json


def faucet_call(port, body, client):
    payload = encode_json({"address": body["address"]}) if body["method"] == "POST" else None
    connection = http.client.HTTPConnection("127.0.0.1", port, timeout=30)
    try:
        connection.request(body["method"], "/faucet", payload,
                           {"Content-Type": "application/json", "X-Zark-Client": client})
        response = connection.getresponse()
        raw = response.read(200_001)
        if len(raw) > 200_000:
            raise ValueError("faucet response limit")
        value = decode_json(raw)
        if not isinstance(value, dict):
            raise ValueError("invalid faucet reply")
        # Return only known public failures, never an upstream exception.
        if response.status != 200:
            code = value.get("error")
            if not isinstance(code, str):
                code = "unavailable"
            status, message = {
                "daily_limit": (429, "Daily test sats limit reached. Try again tomorrow."),
                "empty": (503, "The test sats faucet is empty right now."),
                "invalid_address": (400, "The faucet could not fund this deposit address."),
            }.get(code, (503, "Test sats faucet unavailable. Resume this claim later."))
            return status, {"code": "faucet_" + code if code in ("daily_limit", "empty", "invalid_address") else "faucet_unavailable", "error": message}
        if body["method"] == "GET":
            if (set(value) != {"version", "amount_sat", "available"} or value["version"] != 1
                    or type(value["amount_sat"]) is not int or value["amount_sat"] != 25_000
                    or type(value["available"]) is not bool):
                raise ValueError("invalid faucet offer")
        elif (set(value) != {"version", "transaction"} or value["version"] != 1
              or not isinstance(value["transaction"], str)
              or not re.fullmatch(r"(?:[0-9a-f]{2}){1,100000}", value["transaction"])):
            raise ValueError("invalid faucet transaction")
        return 200, value
    finally:
        connection.close()
