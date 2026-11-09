#!/usr/bin/env python3
"""Regenerate results/ deterministically: python scripts/gen_results.py OUT."""
import csv
import hashlib
import io
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))
from c9lz4 import cases

FILES = ("load.csv", "cleanup.csv", "summary.csv")


def _csv(rows) -> str:
    buf = io.StringIO()
    csv.writer(buf, lineterminator="\n").writerows(rows)
    return buf.getvalue()


def main(out: Path) -> None:
    out.mkdir(parents=True, exist_ok=True)
    data = cases.load()
    rows = [("id", "class", "sticky", "protected_regular", "protected_symlinks",
             "attacker", "version", "outcome", "rule")]
    summary = {}
    for c in data["load"]:
        d = c["dir"]
        for v in ("pre", "post"):
            outcome, rule = cases.run(c, v)
            rows.append((c["id"], c["class"], d["sticky"], d["protected_regular"],
                         d["protected_symlinks"], c["attacker"], v, outcome, rule))
            key = (c["class"], v, outcome)
            summary[key] = summary.get(key, 0) + 1
    (out / "load.csv").write_text(_csv(rows), encoding="utf-8")
    rows = [("id", "class", "version", "deleted", "rule")]
    for c in data["cleanup"]:
        for v in ("pre", "post"):
            rule = "L25,L32-33" if v == "pre" else "L10,L26,L35"
            rows.append((c["id"], c["class"], v,
                         json.dumps(cases.run_cleanup(c, v)), rule))
    (out / "cleanup.csv").write_text(_csv(rows), encoding="utf-8")
    rows = [("class", "version", "outcome", "n")]
    rows += [(*k, summary[k]) for k in sorted(summary)]
    (out / "summary.csv").write_text(_csv(rows), encoding="utf-8")
    sums = [f"{hashlib.sha256((out / n).read_bytes()).hexdigest()}  {n}"
            for n in FILES]
    (out / "SHA256SUMS").write_text("\n".join(sums) + "\n", encoding="utf-8")


if __name__ == "__main__":
    if len(sys.argv) != 2:
        sys.exit("usage: gen_results.py OUTDIR")
    main(Path(sys.argv[1]))
