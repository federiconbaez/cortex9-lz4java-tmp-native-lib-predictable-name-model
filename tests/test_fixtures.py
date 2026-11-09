import json
import unittest

from c9lz4 import cases

DATA = cases.load()
EXPECTED = {}
for line in (cases.ROOT / "fixtures/expected.tsv").read_text(
        encoding="utf-8").splitlines()[1:]:
    kind, cid, ver, val = line.split("\t")
    EXPECTED[(kind, cid, ver)] = val


class Fixtures(unittest.TestCase):
    def test_expected_covers_everything(self):
        n = 2 * (len(DATA["load"]) + len(DATA["cleanup"]))
        self.assertEqual(len(EXPECTED), n)

    def test_load_model_derivation_and_hand_labels_agree(self):
        for c in DATA["load"]:
            for v in ("pre", "post"):
                with self.subTest(case=c["id"], version=v):
                    got, _rule = cases.run(c, v)
                    self.assertEqual(got, EXPECTED[("load", c["id"], v)])
                    self.assertEqual(got, c["expected"][v])

    def test_cleanup_model_derivation_and_hand_labels_agree(self):
        for c in DATA["cleanup"]:
            for v in ("pre", "post"):
                with self.subTest(case=c["id"], version=v):
                    got = cases.run_cleanup(c, v)
                    self.assertEqual(got, json.loads(EXPECTED[("cleanup", c["id"], v)]))
                    self.assertEqual(got, c["expected"][v])

    def test_acceptance_positives_flip(self):
        pos = [c for c in DATA["load"] if c["class"] == "pos"]
        self.assertGreaterEqual(len(pos), 5)
        for c in pos:
            self.assertNotEqual(cases.run(c, "pre")[0], "LOADED_BUNDLED", c["id"])
            self.assertEqual(cases.run(c, "post")[0], "LOADED_BUNDLED", c["id"])

    def test_acceptance_negatives_unchanged(self):
        for c in DATA["load"]:
            if c["class"] == "neg":
                self.assertEqual(cases.run(c, "pre")[0], "LOADED_BUNDLED", c["id"])
                self.assertEqual(cases.run(c, "post")[0], "LOADED_BUNDLED", c["id"])

    def test_native_test_expectations_from_diff(self):
        # NativeTest L211-216: three removed, fresh pair and libother kept.
        c = next(c for c in DATA["cleanup"] if c["id"] == "c01_native_test")
        gone = set(cases.run_cleanup(c, "post"))
        self.assertEqual(gone, {"liblz4-java-123.so", "liblz4-java-123.so.lck",
                                "liblz4-java-456.dll.lck"})
        self.assertNotIn("libother-123.so", gone)


if __name__ == "__main__":
    unittest.main()
