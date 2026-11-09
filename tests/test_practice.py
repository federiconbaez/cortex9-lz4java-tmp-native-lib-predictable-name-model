"""Answers to PRACTICE.md (offline, simulated directory only)."""
import unittest

from c9lz4 import native
from c9lz4.simfs import TmpDir


def run(version, attacker, **d):
    return native.load(TmpDir(**d), version, attacker, ["r1", "r2"])[0]


class Practice(unittest.TestCase):
    def test_level_1_names(self):
        fs = TmpDir()
        native.load(fs, "pre", "none", ["r1"])
        self.assertEqual(sorted(fs.entries),
                         ["liblz4-java-r1.so", "liblz4-java-r1.so.lck"])

    def test_level_2_the_race(self):
        self.assertEqual(run("pre", "plant_file"), "ATTACKER_CODE_LOADED")

    def test_level_3_the_fix(self):
        self.assertEqual(run("post", "plant_file"), "LOADED_BUNDLED")

    def test_level_4_protected_regular(self):
        self.assertEqual(run("pre", "plant_file", protected_regular=1),
                         "DOS_FALLBACK")

    def test_level_5_protected_symlinks(self):
        self.assertEqual(run("pre", "plant_symlink", protected_symlinks=1),
                         "DOS_FALLBACK")
        self.assertEqual(run("pre", "plant_symlink"), "ATTACKER_CODE_LOADED")

    def test_level_6_no_sticky_bit(self):
        self.assertEqual(run("pre", "plant_file", sticky=False,
                             protected_regular=2), "ATTACKER_CODE_LOADED")

    def test_level_7_cleanup(self):
        now = 10 * native.MAX_AGE_MS
        fresh = {"liblz4-java-x.so": now - 60_000}
        self.assertEqual(native.cleanup(fresh, now, "pre"), ["liblz4-java-x.so"])
        self.assertEqual(native.cleanup(fresh, now, "post"), [])


if __name__ == "__main__":
    unittest.main()
