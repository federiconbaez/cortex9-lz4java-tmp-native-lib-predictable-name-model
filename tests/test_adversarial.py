import ast
import builtins
import os
import unittest
from unittest import mock

from c9lz4 import cases, native
from c9lz4.simfs import FsError, TmpDir

BANNED_IMPORTS = {"ctypes", "subprocess", "tempfile", "shutil", "socket"}
BANNED_CALLS = {"open", "system", "popen", "remove", "unlink", "symlink",
                "mkstemp", "load_library", "LoadLibrary", "CDLL", "eval", "exec"}


def _src_files():
    return sorted((cases.ROOT / "src/c9lz4").glob("*.py"))


class Adversarial(unittest.TestCase):
    def test_no_real_filesystem_or_loader_api_in_src(self):
        for f in _src_files():
            tree = ast.parse(f.read_text(encoding="utf-8"))
            for node in ast.walk(tree):
                if isinstance(node, (ast.Import, ast.ImportFrom)):
                    names = [a.name for a in node.names]
                    if isinstance(node, ast.ImportFrom) and node.module:
                        names.append(node.module)
                    for n in names:
                        self.assertNotIn(n.split(".")[0], BANNED_IMPORTS, f.name)
                if isinstance(node, ast.Call):
                    fn = node.func
                    name = fn.attr if isinstance(fn, ast.Attribute) else getattr(
                        fn, "id", "")
                    # the simulated dir's own .unlink/.symlink methods are fine
                    if isinstance(fn, ast.Attribute) and isinstance(
                            fn.value, ast.Name) and fn.value.id in ("fs", "self"):
                        continue
                    if name in BANNED_CALLS:
                        self.fail(f"{f.name}:{getattr(node, 'lineno', 0)} {name}")

    def test_running_every_case_never_touches_the_real_fs(self):
        boom = mock.Mock(side_effect=AssertionError("real fs used"))
        data = cases.load()
        with mock.patch.object(builtins, "open", boom), \
                mock.patch.object(os, "open", boom), \
                mock.patch.object(os, "symlink", boom), \
                mock.patch.object(os, "unlink", boom), \
                mock.patch.object(os, "remove", boom):
            for c in data["load"]:
                for v in native.VERSIONS:
                    cases.run(c, v)
            for c in data["cleanup"]:
                for v in native.VERSIONS:
                    cases.run_cleanup(c, v)
        boom.assert_not_called()

    def test_pre_lib_name_is_the_lck_stem(self):
        fs = TmpDir()
        native.load(fs, "pre", "none", ["r1"])
        self.assertIn("liblz4-java-r1.so.lck", fs.entries)
        self.assertIn("liblz4-java-r1.so", fs.entries)

    def test_post_creates_no_lck(self):
        fs = TmpDir()
        native.load(fs, "post", "none", ["r1"])
        self.assertEqual(sorted(fs.entries), ["liblz4-java-r1.so"])

    def test_post_retries_on_collision_and_skips_symlinks(self):
        fs = TmpDir()
        fs.symlink("liblz4-java-r1.so", "other", "outside:x")
        out, _ = native.load(fs, "post", "none", ["r1", "r2"])
        self.assertEqual(out, "LOADED_BUNDLED")
        self.assertEqual(fs.entries["liblz4-java-r2.so"].owner, "victim")

    def test_post_runs_out_of_names_fails_closed(self):
        fs = TmpDir()
        fs.create_exclusive("liblz4-java-r1.so", "other")
        with self.assertRaises(FsError):
            native.load(fs, "post", "none", ["r1"])

    def test_sysctls_do_nothing_outside_sticky_world_writable_dirs(self):
        for st in (True, False):
            fs = TmpDir(sticky=st, protected_regular=2)
            fs.create_exclusive("x", "other", world_writable=True)
            if st:
                with self.assertRaises(FsError):
                    fs.open_write("x", "victim")
            else:
                self.assertEqual(fs.open_write("x", "victim").owner, "other")

    def test_sticky_bit_blocks_foreign_unlink(self):
        fs = TmpDir(sticky=True)
        fs.create_exclusive("v", "victim")
        with self.assertRaises(FsError):
            fs.unlink("v", "other")

    def test_non_world_writable_victim_file_is_not_writable_by_other(self):
        fs = TmpDir(sticky=False)
        fs.create_exclusive("v", "victim")
        with self.assertRaises(FsError):
            fs.open_write("v", "other")

    def test_unknown_version_rejected(self):
        with self.assertRaises(ValueError):
            native.load(TmpDir(), "v9", "none", ["r"])
        with self.assertRaises(ValueError):
            native.cleanup({}, 0, "v9")

    def test_cleanup_boundary_is_strictly_older_than_one_hour(self):
        now = 10 * native.MAX_AGE_MS
        e = {"liblz4-java-a.so": now - native.MAX_AGE_MS,
             "liblz4-java-b.so": now - native.MAX_AGE_MS - 1}
        self.assertEqual(native.cleanup(e, now, "post"), ["liblz4-java-b.so"])

    def test_cleanup_ignores_similar_prefixes(self):
        e = {"liblz4-javaX.so": 0, "xliblz4-java-1.so": 0}
        self.assertEqual(native.cleanup(e, 10**12, "post"), [])

    def test_deterministic(self):
        data = cases.load()
        a = [cases.run(c, "pre") for c in data["load"]]
        b = [cases.run(c, "pre") for c in data["load"]]
        self.assertEqual(a, b)


if __name__ == "__main__":
    unittest.main()
