# Known limitations

Status at publication, 5 November 2026. This package preserves the experimental
prototype and stored results used by the paper. The following findings remain
open. The smoke tests establish agreement on their tested synthetic cases.

## C4 dependency propagation (fixed)

`Service.taint` declares input-to-output dependencies. In the version published
on 5 November 2026, `verify` and `verify_all` did not propagate them, so an
output without an explicit field label was treated as public even when it
depended on a secret input. Both paths now share `core.c4_update_levels`: a
derived output takes the most sensitive level of its declared inputs, an
explicit label can raise but not lower that level, and declassifiers apply
afterwards. Services that declare no `taint` behave as before.

Run this example from the repository root:

```python
from core import Service, Goal, verify, verify_all
copy = Service("copySecret", "copy", {"secret"}, {"derived"},
               lat_ub=0, lat_mean=0, taint={"derived": {"secret"}})
sink = Service("publicLog", "log", {"derived"}, {"done"},
               lat_ub=0, lat_mean=0, sink_field="derived", sink_clearance="public")
goal = Goal({"secret"}, {"done"}, set(), [], 100,
            init_level={"secret": "secret"})
print(verify([copy, sink], goal))
print(verify_all([copy, sink], goal))
```

The published version returned `ok=True` and no witnesses; the current code
rejects the plan with a `[C4]` witness. `tests/test_c4_taint.py` covers this
case, multi-hop flows, joins, explicit labels, declassifiers before and after
sinks, and benign plans, and checks that 2,904 previously recorded verdicts are
unchanged. The check assumes complete declared flows: undeclared and implicit
flows are still not detected, and these tests do not establish general
soundness. Validation against independently labelled dependency graphs remains
open.

## Implementation and simulation scope

- C1 checks availability of field names. It does not implement JSON Schema subtyping.
- C2 checks propositional facts. Full SMT discharge is timed separately.
- Policy guards are Boolean values. The prototype does not execute Rego policies.
- The dependency false-positive experiment in `exp6_deptaint.py` uses a separate
  synthetic model. Its Boolean rejection simulation is not a call to `core.verify`.
- QWS response times form a bootstrap population for latency simulations. They are
  not joint invocation traces of the evaluated workflows.
- The reduced C1+C2 ablation is internal. It is not an evaluation of Clover.

## Report corrections and remaining implementation work

The revised extended report now distinguishes the full formal design from the
implemented checks. It corrects the repair bound to allow a final successful
proposal after at most N failing proposals, adds the nonnegative path-slack
condition to the DAG Hoeffding expression, and identifies the C1+C2 experiment
as an internal ablation rather than an evaluation of Clover. It also labels the
dependency experiments as separate synthetic simulations.

These are documentation and mathematical-statement corrections. The only
verifier algorithm change is the C4 propagation fix above; rerunning the
model-free experiments with it leaves every stored non-timing value unchanged.
