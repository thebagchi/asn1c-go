"""Oracle vectors for EncodeObjectIdentifier and DecodeObjectIdentifier
(X.690 8.19, X.691 24).

Type: testing.asn1. Output: the key "oid" of testing.json. The arcs are Go ints; the largest is
math.MaxInt64.

Run: testing.py runs this module; see harness.py

Revisions:
  - 2026-10-19 11:42: initial creation
  - 2026-10-20 00:02: read testing.asn1 through harness.py; return the vectors, write no file
  - 2026-10-20 00:43: every row keeps the answers of both oracles, py and er for each variant, with
    expected and derived (see harness.py)
"""

import harness

KIND = "oid"
PREFIX = "Oid"

MAXINT = 2**63 - 1

ARCS = [
    [0, 0],
    [0, 39],
    [1, 0],
    [1, 39],
    [2, 0],
    [2, 39],
    [2, 40],
    [2, 47],
    [2, 48],
    [2, 999],
    [2, 16383],
    [2, 16384],
    [1, 2, 840, 113549, 1, 1, 11],
    [2, 5, 4, 3],
    [1, 3, 6, 1, 4, 1, 2**31 - 1],
    [1, 3, 6, 1, 4, 1, 2**31],
    [1, 3, 6, 1, 4, 1, 2**32],
    [1, 3, 6, 1, 4, 1, 2**53],
    [1, 3, 6, 1, 4, 1, MAXINT],
    [2, 2**31 - 1],
    [2, 2**32],
    [2, 2**53],
    [2, MAXINT - 80],
    [1, 39, 127, 128, 129, 16383, 16384, 2097151, 2097152],
    [1, 3] + list(range(6, 34)),
]

CLAUSES = {}


def vectors():
    module = harness.pycrate_module(PREFIX)
    rows = [{"type": "Oid", "value": arcs} for arcs in ARCS]
    py = harness.pycrate_encode(module, [("Oid", tuple(arcs)) for arcs in ARCS])
    otp = harness.otp_encode(
        PREFIX,
        [("Oid", "{" + ",".join(str(a) for a in arcs) + "}") for arcs in ARCS],
    )
    out = harness.merge(rows, py, otp, CLAUSES)
    return {"oid": out}

