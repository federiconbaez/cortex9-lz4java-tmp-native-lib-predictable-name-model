"""Fixture loading shared by tests and scripts/gen_results.py."""
from __future__ import annotations

import json
from pathlib import Path

from . import native
from .simfs import TmpDir

ROOT = Path(__file__).resolve().parents[2]


def load() -> dict:
    return json.loads((ROOT / "fixtures/cases.json").read_text(encoding="utf-8"))


def make_dir(case: dict) -> TmpDir:
    d = case["dir"]
    return TmpDir(world_writable=d["world_writable"], sticky=d["sticky"],
                  protected_regular=d["protected_regular"],
                  protected_symlinks=d["protected_symlinks"])


def run(case: dict, version: str) -> tuple[str, str]:
    return native.load(make_dir(case), version, case["attacker"],
                       case["randoms"], case.get("guess", ""))


def run_cleanup(case: dict, version: str) -> list:
    return native.cleanup(case["entries"], case["now"], version)
