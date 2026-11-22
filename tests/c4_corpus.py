"""Deterministic plan corpus for the C4 differential test (T10).

The corpus does not depend on core.py: it is built from bench.py and the two
catalogues with fixed seeds. `snapshot()` records what verify/verify_all return
on it. Run this file once on the PRE-fix code to write golden_verdicts_prefix.json:

    cd artifact
    .venv/Scripts/python.exe tests/c4_corpus.py
"""
from __future__ import annotations
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(HERE))
os.environ.pop("VERISAGE_QWS", None)   # catalogues must use their fixed synthetic latencies

import numpy as np                      # noqa: E402
import bench                            # noqa: E402
from catalog import build_catalogue, make_goal                       # noqa: E402
from catalog_hard import build_catalogue_hard, make_goal_hard, REFERENCE  # noqa: E402
from core import verify, verify_all     # noqa: E402

GOLDEN = os.path.join(HERE, "golden_verdicts_prefix.json")
N_RANDOM = 1000
PAYMENT_REFERENCE = ["readCard", "authenticate", "tokenize", "chargeCard",
                     "emailReceipt", "analyticsSink"]


def corpus():
    """Yield (case_id, plan, goal)."""
    for i, (plan, goal, _label, vtype) in enumerate(bench.build_suite(np.random.default_rng(0), 900)):
        yield f"synth/{i}/{vtype}", plan, goal
    for tag, build, goal_fn, ref, base_seed in (
            ("payment", build_catalogue, make_goal, PAYMENT_REFERENCE, 10_000),
            ("regulated", build_catalogue_hard, make_goal_hard, REFERENCE, 20_000)):
        cat = build()
        names = list(cat)
        yield f"{tag}/reference", [cat[n] for n in ref], goal_fn(np.random.default_rng(base_seed - 1))
        yield f"{tag}/all", [cat[n] for n in names], goal_fn(np.random.default_rng(base_seed - 2))
        for i in range(N_RANDOM):
            rng = np.random.default_rng(base_seed + i)
            goal = goal_fn(rng)
            k = int(rng.integers(1, len(names) + 1))
            pick = [names[j] for j in rng.permutation(len(names))[:k]]
            yield f"{tag}/random/{i}", [cat[n] for n in pick], goal


def snapshot():
    out = {}
    for cid, plan, goal in corpus():
        v = verify(plan, goal)
        out[cid] = {"ok": v.ok, "check": v.check, "witness": v.witness,
                    "proof_coverage": v.proof_coverage, "verify_all": verify_all(plan, goal)}
    return out


if __name__ == "__main__":
    snap = snapshot()
    with open(GOLDEN, "w", encoding="utf-8", newline="\n") as f:
        json.dump(snap, f, indent=0, sort_keys=True)
        f.write("\n")
    checks = {}
    for r in snap.values():
        checks[r["check"] or "ok"] = checks.get(r["check"] or "ok", 0) + 1
    print(f"wrote {len(snap)} cases to {GOLDEN}; first failing check counts: {checks}")
