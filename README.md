# cortex9-lz4java-tmp-native-lib-predictable-name-model

Offline, inert model of **CVE-2026-106451** (GHSA-mcr4-qmvw-px4g, CWE-367 /
CWE-377). When no system `liblz4-java` is found, lz4-java's `Native.load()`
extracts the bundled JNI library to `java.io.tmpdir` and `System.load`s it.
Up to 1.11.3 only a `.lck` file got a random, exclusively created name; the
library path was that name minus `.lck` (diff L47-48), nothing reserved it,
and `new FileOutputStream` (L53) opened it with `O_CREAT|O_TRUNC`, following
symlinks. Another local user sharing the temp directory could create it
first. The fix, commit `7a48b7f6b8099b9dab6541e4ac2ee0979dc55aa3` (in
1.11.4), creates the library itself with `File.createTempFile` (L51) and
replaces the `.lck` check in the cleanup with a one-hour age (L10, L35).
Verification: [evidence/verification.md](evidence/verification.md).

Spanish: [README.es.md](README.es.md). Exercises: [PRACTICE.md](PRACTICE.md).

## The model

- `src/c9lz4/simfs.py`: one temp directory **in a Python dict**: exclusive
  create, `O_CREAT|O_TRUNC` opens that follow symlinks, unlink, the sticky
  bit, and `fs.protected_regular` / `fs.protected_symlinks`, which act only
  in world-writable sticky directories.
- `src/c9lz4/native.py`: `load()` pre (L47-48, L53, L56) and post (L51), with
  the other user's strategies from the GHSA (plant a file or a symlink at
  the `.lck` stem), and `cleanup()` pre (L25, L32-33) and post (L10, L26,
  L35).
- **Nothing touches a real directory and no library is loaded**; tests
  patch `open`, `os.open`, `os.symlink`, `os.unlink` and `os.remove` to fail
  and check the source AST for loader and filesystem APIs.

## Differential evidence (`results/summary.csv`)

| Class | n | pre | post |
|---|---|---|---|
| pos | 6 | 4 `ATTACKER_CODE_LOADED`, 2 `DOS_FALLBACK` | 6 `LOADED_BUNDLED` |
| neg | 3 | `LOADED_BUNDLED` | `LOADED_BUNDLED` |
| observation | 1 | `ATTACKER_CODE_LOADED` | `ATTACKER_CODE_LOADED` |

The positives follow the GHSA's host conditions: `protected_regular = 0`
(p01), no sticky bit (p02), a symlink with `protected_symlinks = 0` (p03);
`protected_regular >= 1` (p04) and `protected_symlinks = 1` (p05) turn it
into a denial of service (the Java fallback). p06: pre never checks that
the stem is free, so a file planted in advance at the right name is reused;
post's exclusive create retries instead. `o01` is a **model observation, not
verified**: in a world-writable directory **without** the sticky bit, any
user may unlink and replace any file between write and `System.load`, so the
fix alone does not help there (the GHSA's workaround, a private
`java.io.tmpdir`, does). `results/cleanup.csv` reproduces `NativeTest`
(L211-216) and shows that pre deleted a fresh library without a `.lck`.

## Run

```sh
(cd sources && sha256sum -c SHA256SUMS)
PYTHONPATH=src python3 -m unittest discover -s tests -v
python3 scripts/derive_expected.py | diff - fixtures/expected.tsv
python3 scripts/gen_results.py /tmp/r && diff -r results /tmp/r
```

`fixtures/expected.tsv` comes from `scripts/derive_expected.py`, an
independent decision table built from the GHSA's conditions; it does not
import `src/`. Python 3.10+ standard library only.

A model is not a finding. See [LIMITATIONS.md](LIMITATIONS.md) and
[SOURCES.md](SOURCES.md). License: Apache-2.0.
