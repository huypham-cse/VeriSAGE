"""Regression tests for C4 dependency propagation.

Reference definition (appendix.tex:115-118): C4 accepts iff reachability on the
acyclic data-flow graph built from dep(s_i) (here: Service.taint) finds no path
from a field to a sink cleared below its level that avoids every declassifier.
Every expectation below is derived from that sentence, not from program output.
Cases marked [Qn] depend on a semantic choice listed in notes/proposal-c4.md.

Run from artifact/:  .venv/Scripts/python.exe -m unittest discover -s tests -v
"""
from __future__ import annotations
import json
import os
import sys
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(HERE))

from core import Service, Goal, verify, verify_all  # noqa: E402


def svc(name, req, prod, **kw):
    """Zero-latency service, so C5-SLA never interferes with the C4 cases."""
    return Service(name, name, set(req), set(prod), lat_ub=0, lat_mean=0, **kw)


def sink(name, field, clearance="public", **kw):
    return svc(name, {field}, {name + ".done"}, sink_field=field, sink_clearance=clearance, **kw)


def goal(init, levels):
    return Goal(set(init), set(), set(), [], 100, init_level=dict(levels))


SECRET = goal({"secret"}, {"secret": "secret"})


def case_t1():   # README example: derived depends on secret and reaches a public sink.
    return [svc("copySecret", {"secret"}, {"derived"}, taint={"derived": {"secret"}}),
            sink("publicLog", "derived")], SECRET


def case_t2():   # path secret -> a -> b -> c -> public sink, no declassifier on it.
    return [svc("s1", {"secret"}, {"a"}, taint={"a": {"secret"}}),
            svc("s2", {"a"}, {"b"}, taint={"b": {"a"}}),
            svc("s3", {"b"}, {"c"}, taint={"c": {"b"}}),
            sink("publicLog", "c")], SECRET


def case_t3():   # join: out depends on x (public) and y (secret); the path from y reaches the sink.
    return [svc("join", {"x", "y"}, {"out"}, taint={"out": {"x", "y"}}),
            sink("publicLog", "out")], goal({"x", "y"}, {"y": "secret"})


def case_t4():   # join of two public inputs: no field above the sink's clearance reaches it.
    return [svc("join", {"x", "y"}, {"out"}, taint={"out": {"x", "y"}}),
            sink("publicLog", "out")], goal({"x", "y"}, {"x": "public"})


def case_t5():   # the only path to the sink passes through a declassifier.
    return [svc("copySecret", {"secret"}, {"derived"}, taint={"derived": {"secret"}}),
            svc("anonymise", {"derived"}, {"anon.ok"}, declassifies={"derived"}),
            sink("publicLog", "derived")], SECRET


def case_t6():   # the declassifier runs after the sink, so the path to the sink avoids it.
    return [svc("copySecret", {"secret"}, {"derived"}, taint={"derived": {"secret"}}),
            sink("publicLog", "derived"),
            svc("anonymise", {"derived"}, {"anon.ok"}, declassifies={"derived"})], SECRET


def case_t7():   # [Q3] a lower explicit label does not cut a dep path; only declassifiers can.
    return [svc("copySecret", {"secret"}, {"derived"}, taint={"derived": {"secret"}},
                field_level={"derived": "public"}),
            sink("publicLog", "derived")], SECRET


def case_t8():   # the sink is cleared for secret, so it is not "cleared below" the field's level.
    return [svc("copySecret", {"secret"}, {"derived"}, taint={"derived": {"secret"}}),
            sink("vault", "derived", clearance="secret")], SECRET


def case_t9():   # dependencies but no sink: there is no sink to reach.
    return [svc("copySecret", {"secret"}, {"derived"}, taint={"derived": {"secret"}})], SECRET


def case_t12():  # source labelled by an earlier service (pii), then derived, then public sink.
    return [svc("readCard", set(), {"card.pan"}, field_level={"card.pan": "pii"}),
            svc("format", {"card.pan"}, {"card.str"}, taint={"card.str": {"card.pan"}}),
            sink("publicLog", "card.str")], goal(set(), {})


def case_t13():  # [Q5] the sink service declassifies its own field before exporting it.
    return [svc("copySecret", {"secret"}, {"derived"}, taint={"derived": {"secret"}}),
            sink("anonLog", "derived", declassifies={"derived"})], SECRET


def case_t14():  # two derived fields each reach their own public sink: two violating paths.
    return [svc("copy1", {"secret"}, {"d1"}, taint={"d1": {"secret"}}),
            svc("copy2", {"secret"}, {"d2"}, taint={"d2": {"secret"}}),
            sink("log1", "d1"), sink("log2", "d2")], SECRET


def case_t15():  # [Q6] the field is re-derived from public data before the sink.
    return [svc("copySecret", {"secret"}, {"derived"}, taint={"derived": {"secret"}}),
            svc("recompute", {"pub"}, {"derived"}, taint={"derived": {"pub"}}),
            sink("publicLog", "derived")], goal({"secret", "pub"}, {"secret": "secret"})


REJECT = {"T1": case_t1, "T2": case_t2, "T3": case_t3, "T6": case_t6, "T7": case_t7,
          "T12": case_t12, "T14": case_t14}
ACCEPT = {"T4": case_t4, "T5": case_t5, "T8": case_t8, "T9": case_t9, "T13": case_t13,
          "T15": case_t15}


class C4Propagation(unittest.TestCase):

    def assertRejectsC4(self, plan, g):
        v = verify(plan, g)
        self.assertFalse(v.ok, "verify admitted a plan with a violating flow path")
        self.assertEqual(v.check, "C4", v.witness)
        w = verify_all(plan, g)
        self.assertTrue(w, "verify_all returned no witness")
        self.assertTrue(all(x.startswith("[C4]") for x in w), w)   # cases isolate C4

    def assertAccepts(self, plan, g):
        v = verify(plan, g)
        self.assertTrue(v.ok, f"{v.check}: {v.witness}")
        self.assertEqual(verify_all(plan, g), [])

    def test_t1_readme_example(self):
        self.assertRejectsC4(*case_t1())

    def test_t2_multi_hop(self):
        self.assertRejectsC4(*case_t2())

    def test_t3_join_takes_max(self):
        plan, g = case_t3()
        self.assertRejectsC4(plan, g)
        self.assertIn("(secret)", verify(plan, g).witness)   # level of the join is the max input

    def test_t4_join_all_public(self):
        self.assertAccepts(*case_t4())

    def test_t5_declassifier_before_sink(self):
        self.assertAccepts(*case_t5())

    def test_t6_declassifier_after_sink(self):
        self.assertRejectsC4(*case_t6())

    def test_t7_explicit_lower_label_does_not_launder(self):
        self.assertRejectsC4(*case_t7())

    def test_t8_secret_cleared_sink(self):
        self.assertAccepts(*case_t8())

    def test_t9_taint_without_sink(self):
        self.assertAccepts(*case_t9())

    def test_t11_verify_and_verify_all_agree(self):
        for name, fn in {**REJECT, **ACCEPT}.items():
            with self.subTest(case=name):
                plan, g = fn()
                v = verify(plan, g)
                has_c4 = any(x.startswith("[C4]") for x in verify_all(plan, g))
                self.assertEqual(v.check == "C4", has_c4)

    def test_t12_label_from_earlier_service(self):
        plan, g = case_t12()
        self.assertRejectsC4(plan, g)
        self.assertIn("(pii)", verify(plan, g).witness)

    def test_t13_self_declassifying_sink(self):
        self.assertAccepts(*case_t13())

    def test_t14_verify_all_reports_every_leak(self):
        plan, g = case_t14()
        self.assertRejectsC4(plan, g)
        self.assertIn("log1", verify(plan, g).witness)       # verify stops at the first sink
        self.assertEqual(len(verify_all(plan, g)), 2)

    def test_t15_rederived_from_public(self):
        self.assertAccepts(*case_t15())


class C4Unchanged(unittest.TestCase):
    """T10: on plans without declared dependencies, nothing may change."""

    def test_t10_golden_verdicts_identical(self):
        import c4_corpus
        with open(c4_corpus.GOLDEN, encoding="utf-8") as f:
            golden = json.load(f)
        now = c4_corpus.snapshot()
        self.assertEqual(sorted(now), sorted(golden), "corpus case ids changed")
        diff = [cid for cid in golden if golden[cid] != now[cid]]
        self.assertEqual(diff, [], f"{len(diff)} verdicts changed, first: {diff[:5]}")


if __name__ == "__main__":
    unittest.main()
