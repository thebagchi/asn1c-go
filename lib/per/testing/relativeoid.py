"""Oracle vectors for EncodeRelativeOID and DecodeRelativeOID
(X.690 8.20, X.691 25).

Type: testing.asn1. Output: the key "relativeoid" of testing.json. The empty list is not a
row: X.680 clause 33 gives a RELATIVE-OID value one or more components
(RelativeOIDComponentsList), so the Go tests treat it as a refusal.

Run: testing.py runs this module; see harness.py

Revisions:
  - 2026-10-19 11:42: initial creation
  - 2026-10-20 00:02: read testing.asn1 through harness.py; return the vectors, write no file
  - 2026-10-20 00:43: every row keeps the answers of both oracles, py and er for each variant, with
    expected and derived (see harness.py)
"""

import harness

KIND = "relativeoid"
PREFIX = "Reloid"

MAXINT = 2**63 - 1

ARCS = [
    [0],
    [1],
    [127],
    [128],
    [5, 6],
    [8571, 3, 2],
    [16383, 16384],
    [0, 0, 0],
    [2**31 - 1],
    [2**31],
    [2**32],
    [2**53],
    [MAXINT],
    [1, MAXINT],
    [40, 47, 48, 80],
    list(range(30)),
]

CLAUSES = {}


def vectors():
    module = harness.pycrate_module(PREFIX)
    rows = [{"type": "Rel", "value": arcs} for arcs in ARCS]
    py = harness.pycrate_encode(module, [("Rel", tuple(arcs)) for arcs in ARCS])
    otp = harness.otp_encode(
        PREFIX,
        [("Rel", "[" + ",".join(str(a) for a in arcs) + "]") for arcs in ARCS],
    )
    out = harness.merge(rows, py, otp, CLAUSES)
    return {"relative_oid": out}

