"""Oracle vectors for the lib/per Phase 3 regression tests (P3-2, P3-3, P3-5).

pycrate 0.8.1 and Erlang/OTP 29.1.1 both encode each value in APER and UPER
from the types of testing.asn1. A disagreement stops the run. Output: the key
"regression" of testing.json, which TestRegression_* in lib/per/regression_p3_test.go
reads. OTP reads a UniversalString as a list of characters; a code point above
0xFFFF is the tuple {group, plane, row, cell}.

Run: testing.py runs this module; see harness.py

Revisions:
  - 2026-10-19 11:20: initial creation
  - 2026-10-20 00:06: ask OTP in the same run and read testing.asn1
    through harness.py; return the vectors, write no file
  - 2026-10-20 00:43: every row keeps the answers of both oracles, py and er for each variant, with
    expected and derived (see harness.py)
"""

import harness

KIND = "regression"
PREFIX = "Regression"

INT_MIN = -(2**63)
INT_MAX = 2**63 - 1

# (type, python value, JSON value, lb, ub)
INTEGERS = [
    ("Full", INT_MIN, INT_MIN, INT_MIN, INT_MAX),
    ("Full", -1, -1, INT_MIN, INT_MAX),
    ("Full", 0, 0, INT_MIN, INT_MAX),
    ("Full", 1, 1, INT_MIN, INT_MAX),
    ("Full", INT_MAX, INT_MAX, INT_MIN, INT_MAX),
    ("MinusOne", -1, -1, -1, INT_MAX),
    ("MinusOne", 0, 0, -1, INT_MAX),
    ("MinusOne", INT_MAX, INT_MAX, -1, INT_MAX),
    ("Zero", 0, 0, 0, INT_MAX),
    ("Zero", 1, 1, 0, INT_MAX),
    ("Zero", INT_MAX, INT_MAX, 0, INT_MAX),
]

# (type, text, lb, ub); lb and ub are the SIZE bounds, None for no SIZE.
STRINGS = [
    ("Uni", "", None, None),
    ("Uni", "a", None, None),
    ("Uni", "hi", None, None),
    ("Uni", "a\U0001f600", None, None),
    ("UniSize", "a", 1, 4),
    ("UniSize", "abcd", 1, 4),
    ("UniSize", "a\U0001f600", 1, 4),
    ("UniFixed", "abc", 3, 3),
    ("UniFixed", "a\U0001f600z", 3, 3),
]


def otp_char(code):
    """An OTP UniversalString character: an integer, or a tuple above 0xFFFF."""
    if code > 0xFFFF:
        return "{%d,%d,%d,%d}" % ((code >> 24) & 255, (code >> 16) & 255, (code >> 8) & 255, code & 255)
    return str(code)


def otp_text(text):
    return "[" + ",".join(otp_char(ord(c)) for c in text) + "]"


def answers(rows):
    """Ask both oracles for rows of (type, python value, Erlang text); return merged JSON rows."""
    module = harness.pycrate_module(PREFIX)
    py = harness.pycrate_encode(module, [(name, value) for name, value, _ in rows])
    otp = harness.otp_encode(PREFIX, [(name, text) for name, _, text in rows])
    return py, otp


def vectors():
    out = {"integers": [], "strings": [], "empty": []}

    asked = [(name, value, str(value)) for name, value, _, _, _ in INTEGERS]
    asked += [(name, text, otp_text(text)) for name, text, _, _ in STRINGS]
    asked += [("Null", 0, "'NULL'"), ("Single", 5, "5")]
    py, otp = answers(asked)
    shown = [{"type": name, "value": value, "lb": lb, "ub": ub} for name, _, value, lb, ub in INTEGERS]
    shown += [{"type": name, "value": text, "lb": lb, "ub": ub} for name, text, lb, ub in STRINGS]
    # X.691 11.1.3.1: an empty complete encoding is one octet 0x00.
    shown += [{"type": "Null"}, {"type": "Single", "value": 5}]
    merged = harness.merge(shown, py, otp, {})
    out["integers"] = merged[: len(INTEGERS)]
    out["strings"] = merged[len(INTEGERS) : len(INTEGERS) + len(STRINGS)]
    out["empty"] = merged[len(INTEGERS) + len(STRINGS) :]
    return out
