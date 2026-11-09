"""Native.load() and cleanupOldTempLibs() of lz4-java, before and after
commit 7a48b7f6b8099b9dab6541e4ac2ee0979dc55aa3 (CVE-2026-106451).

Lnnn = `cat -n` line of sources/CVE-2026-106451_lz4-java_7a48b7f6b809.diff.
No library is extracted or loaded: "loading" means reading which entry of
the simulated directory System.load would map, and who controls it.
"""
from __future__ import annotations

from .simfs import OUTSIDE, Entry, FsError, TmpDir

VERSIONS = ("pre", "post")
PREFIX = "liblz4-java-"  # L47 / L51
EXT = "so"  # os().libExtension on Linux
BUNDLED = "BUNDLED"  # content written from the jar
ATTACKER = "ATTACKER"  # marker for content the other user controls
MAX_AGE_MS = 60 * 60 * 1000  # L10


def _create_temp(fs: TmpDir, suffix: str, randoms: list) -> str:
    """File.createTempFile: random name, exclusive create, retry on EEXIST."""
    for r in randoms:
        name = f"{PREFIX}{r}{suffix}"
        try:
            fs.create_exclusive(name, "victim")
            return name
        except FsError as e:
            if e.errno != "EEXIST":
                raise
    raise FsError("EEXIST", "model ran out of random names")


# --- attacker strategies (the other local user) ---------------------------
def _plant(fs: TmpDir, attacker: str, name: str) -> None:
    try:
        if attacker == "plant_file":
            fs.create_exclusive(name, "other", world_writable=True,
                                content=ATTACKER)
        elif attacker == "plant_symlink":
            tgt = f"{OUTSIDE}{name}"
            fs.outside.setdefault(tgt, _outside_file())
            fs.symlink(name, "other", tgt)
    except FsError as e:
        fs.log.append(f"other plant failed: {e.errno}")


def _outside_file() -> Entry:
    return Entry("file", "other", world_writable=True, content=ATTACKER)


def _after_write(fs: TmpDir, attacker: str, name: str) -> None:
    """The GHSA: the other user can overwrite a file they own before load."""
    target = fs.resolve(name)
    if attacker in ("plant_file", "plant_symlink") and target is not None \
            and target.owner == "other":
        target.content = ATTACKER
        fs.log.append("other overwrites its own file")
    if attacker == "replace_after_write":
        try:
            fs.unlink(name, "other")
            fs.create_exclusive(name, "other", content=ATTACKER)
        except FsError as e:
            fs.log.append(f"other replace failed: {e.errno}")


def load(fs: TmpDir, version: str, attacker: str, randoms: list,
         guess: str = "") -> tuple[str, str]:
    """Return (outcome, rule). Outcomes: LOADED_BUNDLED,
    ATTACKER_CODE_LOADED, DOS_FALLBACK (open failed, Java fallback)."""
    if version not in VERSIONS:
        raise ValueError(version)
    if attacker == "preplant_guess" and guess:
        _plant(fs, "plant_file", guess)
    if version == "pre":
        lck = _create_temp(fs, f".{EXT}.lck", randoms)  # L47
        lib = lck[: -len(".lck")]  # L48: derived, never reserved
        rule = "L47-48,L53"
        if attacker in ("plant_file", "plant_symlink"):
            _plant(fs, attacker, lib)  # the race the GHSA describes
    else:
        lib = _create_temp(fs, f".{EXT}", randoms)  # L51
        rule = "L51,L53"
        if attacker in ("plant_file", "plant_symlink"):
            _plant(fs, attacker, lib)  # fails: the name is already taken
    try:
        out = fs.open_write(lib, "victim")  # L53 FileOutputStream
    except FsError as e:
        fs.log.append(f"victim open failed: {e.why}")
        return "DOS_FALLBACK", f"{rule} ({e.why})"
    out.content = BUNDLED
    _after_write(fs, attacker, lib)
    final = fs.resolve(lib)  # L56 System.load
    if final is None:
        return "DOS_FALLBACK", f"{rule} (missing at load)"
    if final.owner != "victim" or final.content != BUNDLED:
        return "ATTACKER_CODE_LOADED", f"{rule},L56"
    return "LOADED_BUNDLED", f"{rule},L56"


def cleanup(entries: dict, now: int, version: str) -> list:
    """Names deleted by cleanupOldTempLibs. entries: {name: mtime}."""
    if version not in VERSIONS:
        raise ValueError(version)
    deleted = []
    for name in sorted(entries):
        if version == "pre":
            # L25: skip .lck; L32-33: delete when no sibling .lck exists
            if (name.startswith(PREFIX) and not name.endswith(".lck")
                    and name + ".lck" not in entries):
                deleted.append(name)
        else:
            # L26: every liblz4-java-* name; L35: older than one hour
            if name.startswith(PREFIX) and now - entries[name] > MAX_AGE_MS:
                deleted.append(name)
    return deleted
