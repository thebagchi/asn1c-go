"""Oracle vectors for EncodeBoolean and DecodeBoolean (X.691 12).

One type, BOOLEAN-PLAIN of testing.asn1, and both values. pycrate 0.8.1 and Erlang/OTP 29.1.1
both encode each value in APER and UPER, and the run stops when they differ. Output: the key
"bool" of testing.json; a row is {type, input, aper, uper, ...} in the form of harness.py.

Run: testing.py runs this module; see harness.py

Revisions:
  - 2026-09-22 06:43: initial creation
  - 2026-10-20 00:13: ask both oracles for both variants from testing.asn1; one row for each value
    instead of a row for each variant; return the vectors, write no file
  - 2026-10-20 00:43: every row keeps the answers of both oracles, py and er for each variant, with
    expected and derived (see harness.py)
"""

import harness

KIND = "bool"
PREFIX = ""

TYPE = "BOOLEAN-PLAIN"
VALUES = [True, False]


def vectors():
    module = harness.pycrate_module(PREFIX)
    rows = [{"type": TYPE, "input": value} for value in VALUES]
    py = harness.pycrate_encode(module, [(TYPE, value) for value in VALUES])
    otp = harness.otp_encode(PREFIX, [(TYPE, "true" if value else "false") for value in VALUES])
    return harness.merge(rows, py, otp, {})
