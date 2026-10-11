import unittest
from observation import collect, validate_request


class ObservationTests(unittest.TestCase):
    def test_bounded_reads_fence_even_errors_and_include_mempool(self):
        params = ["1", "66" * 32, "0", "77" * 32, "2"]
        for active, failed in [(None, False), ({"confirmations": 0}, False), (None, True)]:
            calls = []

            def rpc(method, args):
                calls.append((method, args))
                if method == "getblockchaininfo":
                    return {"blocks": 200, "bestblockhash": "44" * 32}
                if method == "getrawtransaction":
                    return {"confirmations": 100}
                if method == "gettxout":
                    self.assertEqual(args[2], "true")
                    if failed:
                        raise ValueError("secret operator text")
                    return active
                return "aa" * 32

            result = collect(params, rpc)
            self.assertEqual(result["request"], params)
            self.assertEqual(calls[0], ("getblockchaininfo", []))
            self.assertEqual(calls[-1], ("getblockchaininfo", []))
            self.assertEqual(calls[3], ("getblockhash", ["101"]))
            self.assertEqual(len(calls), 7 if active is None else 6)
            self.assertEqual(result["reads"][4]["failed"], failed)
            self.assertNotIn("secret", str(result))

    def test_request_has_no_arbitrary_methods_or_rpc_parameters(self):
        for params in [None, [], ["1", "66" * 32, "0", "77" * 32, "0", "stop"],
                       ["1", "66" * 32, "0", "77" * 32, "4294967296"],
                       ["1", "66" * 32, "1", "77" * 32, "0"],
                       ["1", "66" * 32, "0", "77" * 32, "01"]]:
            with self.assertRaises(ValueError):
                validate_request(params)


if __name__ == "__main__":
    unittest.main()
