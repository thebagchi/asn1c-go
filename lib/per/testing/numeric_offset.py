"""Oracle vectors for a NumericString that starts at every bit offset (X.691 30.5).

The types are Numoff-<k>-<form>[-<n>] of testing.asn1: k BOOLEAN components (k = 0 to 7) and
then a NumericString, so the characters start k bits into the encoding. The forms are U (no
SIZE), F-n (SIZE (n)) and R-n (SIZE (0..n+7)). Every BOOLEAN is TRUE. pycrate 0.8.1 and
Erlang/OTP 29.1.1 both encode each row in APER and UPER, and the run stops when they differ.
Output: the key "numeric_offset" of testing.json; a row is {type, offset, form, length, seed,
aper, uper, ...} in the form of harness.py.

The characters follow one rule, which the Go test (numeric_offset_test.go) repeats: character
i of a value is " 0123456789"[(7 * i + seed) % 11], with seed = (3 * offset + length) % 11.

These rows replace a golden file, whose octets came from an earlier encoder and
not from an oracle.

Run: testing.py runs this module; see harness.py

Revisions:
  - 2026-10-20 13:57: initial creation
"""

import harness

KIND = "numeric_offset"
PREFIX = "Numoff"

OFFSETS = range(8)
LENGTHS = [0, 1, 2, 3, 4, 7, 8, 15, 16, 17, 31, 32, 33, 47, 48, 63, 64, 65, 100, 129, 256, 257, 300, 1000]
FORMS = ["U", "F", "R"]
ALPHABET = " 0123456789"
STRIDE = 7
SEED_OFFSET = 3
NUMERIC_BITS = 4
ALIGN_LIMIT = 16


def text(offset, length):
    """The value of a row: length characters of the rule above."""
    seed = (SEED_OFFSET * offset + length) % len(ALPHABET)
    return seed, "".join(ALPHABET[(STRIDE * i + seed) % len(ALPHABET)] for i in range(length))


def short(offset, form, length):
    """The short name of the type of a row in testing.asn1."""
    if form == "U":
        return f"{offset}-U"
    return f"{offset}-{form}-{length}"


def py_value(offset, value):
    if offset == 0:
        return value
    fields = {f"b{i}": True for i in range(1, offset + 1)}
    fields["s"] = value
    return fields


def erl_value(offset, form, length, value):
    chars = "[" + ",".join(str(ord(c)) for c in value) + "]"
    if offset == 0:
        return chars
    name = harness.full_name(PREFIX, short(offset, form, length))
    return "{'" + name + "'" + ",true" * offset + "," + chars + "}"


def decide(row):
    """Decide a row where the oracles differ, or return None to stop the run.

    X.691 30.5.6: a fixed size whose aub * b is not above 16 is a bit-field that is not
    octet-aligned. pycrate aligns it anyway after a BOOLEAN (the fault of review P5-3); OTP
    does not. Only that case is decided here.
    """
    if row["form"] == "F" and NUMERIC_BITS * row["length"] <= ALIGN_LIMIT:
        return ("otp", "X.691 30.5.6: aub * b <= 16, so the field is not octet-aligned (pycrate aligns it)")
    return None


def vectors():
    module = harness.pycrate_module(PREFIX)
    rows, py_rows, er_rows = [], [], []
    for offset in OFFSETS:
        for form in FORMS:
            for length in LENGTHS:
                seed, value = text(offset, length)
                kind = short(offset, form, length)
                rows.append({"type": kind, "offset": offset, "form": form, "length": length, "seed": seed})
                py_rows.append((kind, py_value(offset, value)))
                er_rows.append((kind, erl_value(offset, form, length, value)))
    py = harness.pycrate_encode(module, py_rows)
    otp = harness.otp_encode(PREFIX, er_rows)
    return [unaligned(row) for row in harness.merge(rows, py, otp, decide)]


def unaligned(row):
    """Correct the APER answer of a short fixed size that both oracles align.

    X.691 30.5.6 and the NOTE to 30.5.7: a fixed size whose aub * b is not above 16 is not
    octet-aligned, and exactly 16 also stays unaligned. Such a field then has the same bits in
    APER as in UPER: no length, one bit for each BOOLEAN, four bits for each character, no
    pad. When both oracles pad the APER field (aub * b = 16 after a BOOLEAN), the expected
    APER answer is the UPER answer that both oracles give.
    """
    short_fixed = row["form"] == "F" and NUMERIC_BITS * row["length"] <= ALIGN_LIMIT
    if not short_fixed:
        return row
    uper = harness.expected(row, "uper")
    if harness.expected(row, "aper") == uper:
        return row
    row["expected"] = {"aper": "derived"}
    row["derived"] = {"aper": uper, "how": "the UPER answer of both oracles: the same bits as APER here"}
    row["decided_by"] = "X.691 30.5.6 and the NOTE to 30.5.7: aub * b = 16 is not octet-aligned"
    return row
