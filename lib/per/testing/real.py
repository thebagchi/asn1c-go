"""Oracle vectors for EncodeReal and DecodeReal (X.691 15, X.690 8.5).

One type, FLOAT-64 of testing.asn1 (REAL). A finite value is given to both oracles as the
(mantissa, 2, exponent) of its IEEE 754 bits with an odd mantissa, the form of CER and DER
(X.690 11.3.1), and zero as (0, 10, 0) for pycrate and 0 for OTP (OTP reads {0, 10, 0} as decimal). pycrate 0.8.1 and Erlang/OTP 29.1.1 both encode each
one in APER and UPER, and the run stops when they differ. The four special values are
PLUS-INFINITY, MINUS-INFINITY, NOT-A-NUMBER and minus zero (X.690 8.5.9: the contents octet
0x40, 0x41, 0x42 and 0x43 behind an unconstrained length). pycrate cannot encode any of them,
OTP encodes the first two (the atoms PLUS-INFINITY and MINUS-INFINITY) and neither of the
last two, so their octets are those of the clause; the row keeps the clause octets as derived
and the run stops when OTP answers differently. Output: the key "real" of testing.json; a row
is {type, input {value}, aper, uper, ...} in the form of harness.py, where value is a number or Inf, -Inf, NaN
or -0.

Run: testing.py runs this module; see harness.py

Revisions:
  - 2026-09-22 06:43: initial creation
  - 2026-10-20 00:13: read the type from testing.asn1 and ask both oracles for every value (the lists of
    the pycrate run and the OTP run are one list); one row for each value instead of a row for each variant; the special
    values have a row with the octets of X.690 8.5.9, asked of OTP where it can encode them; return the
    vectors, write no file
  - 2026-10-20 00:43: every row keeps the answers of both oracles, py and er for each variant, with
    expected and derived (see harness.py)
"""

import struct

import harness

KIND = "real"
PREFIX = ""

TYPE = "FLOAT-64"

VALUES = [
    0.0, 1.0, 2.0, 3.0, -1.0, -2.0, -3.0, 0.5, 0.25, 0.125, 4.0, 8.0, 16.0, 256.0, 1024.0, 65536.0,
    1.5, 2.5, 3.75, -0.5, -1.5, -3.75, 10.0, 100.0, 1000.0, -10.0, -100.0, 1e-10, 1e-20, -1e-10,
    10000000000.0, 1e+20, 1e+50, -10000000000.0, -1e+20, 1e+100, 1e+200, 1e-100, 1e-200, -1e+100,
    3.141592653589793, 2.718281828459045, -3.141592653589793, 1.7976931348623157e+308,
    -1.7976931348623157e+308, 2.2250738585072014e-308, 5e-324, -5e-324, -2.2250738585072014e-308
]

# label -> (Erlang term of OTP or None, the length octet and the contents octet of X.690 8.5.9)
SPECIAL = {
    "Inf": ("'PLUS-INFINITY'", "0140"),
    "-Inf": ("'MINUS-INFINITY'", "0141"),
    "NaN": (None, "0142"),
    "-0": (None, "0143"),
}


def real_tuple(value):
    """The (mantissa, base, exponent) of a float64 with an odd mantissa (X.690 11.3.1)."""
    if value == 0.0:
        return (0, 10, 0)
    bits = struct.unpack(">Q", struct.pack(">d", value))[0]
    sign = (bits >> 63) & 1
    biased = (bits >> 52) & 0x7FF
    fraction = bits & 0xFFFFFFFFFFFFF
    if biased == 0:
        mantissa = fraction
        exponent = -1022 - 52
    else:
        mantissa = (1 << 52) | fraction
        exponent = biased - 1023 - 52
    if sign == 1:
        mantissa = -mantissa
    while mantissa != 0 and mantissa % 2 == 0:
        mantissa //= 2
        exponent += 1
    return (mantissa, 2, exponent)


def special_rows():
    """The rows of the special values: octets of the clause, checked against OTP where it answers."""
    terms = [(TYPE, term) for term, _ in SPECIAL.values() if term is not None]
    answers = iter(harness.otp_encode(PREFIX, terms))
    rows = []
    for label, (term, octets) in SPECIAL.items():
        row = {"type": TYPE, "input": {"value": label}}
        er = None
        if term is not None:
            er = next(answers)
            if er != (octets, octets):
                raise SystemExit(f"OTP gave {er} for {label}, the clause gives {octets}")
        row.update(
            harness.compose(
                ("error not encodable", "error not encodable"),
                er,
                clause="X.690 8.5.9: pycrate cannot encode it; OTP, where it can, agrees with the clause",
                derived={"aper": octets, "uper": octets, "how": "X.690 8.5.9: length 1, contents octet of the special value"},
                expected={"aper": "derived", "uper": "derived"},
            )
        )
        rows.append(row)
    return rows


def vectors():
    module = harness.pycrate_module(PREFIX)
    rows = [{"type": TYPE, "input": {"value": value}} for value in VALUES]
    tuples = [real_tuple(value) for value in VALUES]
    py = harness.pycrate_encode(module, [(TYPE, item) for item in tuples])
    otp = harness.otp_encode(PREFIX, [(TYPE, "0" if item[0] == 0 else "{%d,%d,%d}" % item) for item in tuples])
    return harness.merge(rows, py, otp, {}) + special_rows()
