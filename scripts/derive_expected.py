"""Independent expectations for fixtures/cases.json.

Does not import src/. Instead of simulating a directory it applies, as a
decision table, the conditions the GHSA and the saved diff state:

* pre (L47-48): the library name is the .lck name minus ".lck"; nothing
  reserves it, and FileOutputStream (L53) opens it with O_CREAT|O_TRUNC,
  following symlinks.
* post (L51): the library itself is created exclusively with a random name.
* fs.protected_regular / fs.protected_symlinks only act inside
  world-writable sticky directories.

Prints fixtures/expected.tsv. Python 3.10+ standard library only.
"""

import json
import pathlib

ROOT = pathlib.Path(__file__).resolve().parent.parent
HOUR_MS = 3_600_000


def outcome(case, version):
    d = case["dir"]
    others_can_write = d["world_writable"]
    shared_sticky = d["world_writable"] and d["sticky"]
    how = case["attacker"]
    if not others_can_write or how == "none":
        return "LOADED_BUNDLED"
    if how == "replace_after_write":
        # unlink of someone else's file is refused only by the sticky bit
        return "LOADED_BUNDLED" if d["sticky"] else "ATTACKER_CODE_LOADED"
    if version == "post":
        # O_EXCL on a random name: a planted entry is never reused
        return "LOADED_BUNDLED"
    if how == "preplant_guess":
        first_stem = "liblz4-java-" + case["randoms"][0] + ".so"
        if case["guess"] != first_stem:
            return "LOADED_BUNDLED"
        how = "plant_file"
    if how == "plant_file":
        blocked = shared_sticky and d["protected_regular"] >= 1
    elif how == "plant_symlink":
        blocked = shared_sticky and d["protected_symlinks"] >= 1
    else:
        raise SystemExit("unknown attacker " + how)
    return "DOS_FALLBACK" if blocked else "ATTACKER_CODE_LOADED"


def removed(case, version):
    names = case["entries"]
    out = []
    for n in sorted(names):
        ours = n[: len("liblz4-java-")] == "liblz4-java-"
        if version == "post":
            if ours and case["now"] - names[n] > HOUR_MS:
                out.append(n)
        else:
            is_lock = n[-4:] == ".lck"
            if ours and not is_lock and (n + ".lck") not in names:
                out.append(n)
    return out


def main():
    data = json.loads((ROOT / "fixtures/cases.json").read_text(encoding="utf-8"))
    print("kind\tid\tversion\texpected")
    for c in data["load"]:
        for v in ("pre", "post"):
            print(f"load\t{c['id']}\t{v}\t{outcome(c, v)}")
    for c in data["cleanup"]:
        for v in ("pre", "post"):
            print(f"cleanup\t{c['id']}\t{v}\t{json.dumps(removed(c, v))}")


if __name__ == "__main__":
    main()
