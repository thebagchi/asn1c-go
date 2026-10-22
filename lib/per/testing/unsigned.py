"""Oracle vectors for EncodeUnsigned and DecodeUnsigned (X.691 11.5, 11.7, 13).

Ranges are in testing.asn1. Per range the values are the bounds, their
neighbours, the middle, and the edges of the powers of two inside the range.
Output: the key "unsigned" of testing.json. lb and ub are decimal numbers; ub is null for a
semi-constrained range (lb..MAX).

Run: testing.py runs this module; see harness.py

Revisions:
  - 2026-10-19 11:40: initial creation
  - 2026-10-20 00:02: read testing.asn1 through harness.py; return the vectors, write no file
  - 2026-10-20 00:43: every row keeps the answers of both oracles, py and er for each variant, with
    expected and derived (see harness.py)
"""

import harness

KIND = "unsigned"
PREFIX = "Unsigned"

MAX = 2**64 - 1

# type -> (lb, ub); ub None for lb..MAX.
RANGES = {
    "Full": (0, MAX),
    "High": (2**63, MAX),
    "Byte": (0, 255),
    "Wide": (0, 256),
    "Short": (0, 65535),
    "Long": (0, 65536),
    "Single": (1000, 1000),
    "Semi": (0, None),
    "SemiHigh": (2**63, None),
}

CLAUSES = {}


def values(lb, ub):
    top = MAX if ub is None else ub
    found = {lb, lb + 1, top - 1, top, lb + (top - lb) // 2}
    for bits in (1, 2, 3, 4, 7, 8, 9, 15, 16, 17, 24, 31, 32, 33, 40, 48, 55, 56, 57, 62, 63, 64):
        edge = 2**bits
        found.update({edge - 1, edge, edge + 1})
    return sorted(v for v in found if lb <= v <= top)


def vectors():
    module = harness.pycrate_module(PREFIX)
    rows = []
    for kind, (lb, ub) in RANGES.items():
        for value in values(lb, ub):
            rows.append({"type": kind, "lb": lb, "ub": ub, "value": value})

    py = harness.pycrate_encode(module, [(r["type"], r["value"]) for r in rows])
    otp = harness.otp_encode(PREFIX, [(r["type"], str(r["value"])) for r in rows])
    out = harness.merge(rows, py, otp, CLAUSES)
    return {"unsigned": out}

