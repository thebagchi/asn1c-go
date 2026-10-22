"""Oracle vectors for EncodeEnumerated and DecodeEnumerated (X.691 14).

One type of testing.asn1 for each shape: ENUM-<root count>-<extension count>-FALSE (no extension
marker, extension count 0) or ENUM-<root count>-<extension count>-TRUE. The members are m-1,
m-2, ...: the value i is the member m-(i+1), in the root first and then in the extension
(the extension values of a root count are the values from that count up). pycrate 0.8.1 and
Erlang/OTP 29.1.1 both encode every value in APER and UPER, and the run stops when they differ.
Output: the key "enumerated" of testing.json; a row is {type, input {value, count,
extensible}, aper, uper, ...} in the form of harness.py.

Run: testing.py runs this module; see harness.py

Revisions:
  - 2026-09-22 06:43: initial creation
  - 2026-10-20 00:13: read the types from testing.asn1 and ask both oracles for every value (the lists of
    the pycrate run and the OTP run are one list); one row for each value instead of a row for each variant; return the
    vectors, write no file
  - 2026-10-20 00:43: every row keeps the answers of both oracles, py and er for each variant, with
    expected and derived (see harness.py)
"""

import harness

KIND = "enumerated"
PREFIX = ""

# root count -> extension count, for the extensible shapes.
EXT_COUNTS = {1: 1, 2: 2, 3: 2, 4: 256, 7: 2, 17: 2, 128: 4, 129: 2}

# (root count, extensible) -> the values.
SHAPES = {
    (2, False): [
        0, 1
    ],
    (4, False): [
        0, 1, 2, 3
    ],
    (8, False): [
        0, 3, 7
    ],
    (16, False): [
        0, 7, 15
    ],
    (128, False): [
        0, 63, 127
    ],
    (256, False): [
        0, 127, 255
    ],
    (4, True): [
        0, 1, 2, 3, 4, 5, 6, 66, 67, 68, 69, 131, 132, 259
    ],
    (2, True): [
        0, 1, 2, 3
    ],
    (128, True): [
        0, 63, 127, 128, 129, 131
    ],
    (1, True): [
        1, 0
    ],
    (3, False): [
        0, 1, 2
    ],
    (5, False): [
        0, 4
    ],
    (6, False): [
        0, 5
    ],
    (7, False): [
        0, 6
    ],
    (9, False): [
        0, 8
    ],
    (10, False): [
        0, 9
    ],
    (15, False): [
        0, 14
    ],
    (17, False): [
        0, 16
    ],
    (33, False): [
        0, 32
    ],
    (65, False): [
        0, 64
    ],
    (129, False): [
        0, 128
    ],
    (255, False): [
        0, 254
    ],
    (3, True): [
        0, 2, 3, 4
    ],
    (7, True): [
        0, 6, 7, 8
    ],
    (17, True): [
        0, 16, 17, 18
    ],
    (129, True): [
        0, 128, 129, 130
    ],
}


def type_name(count, ext):
    if ext:
        return f"ENUM-{count}-{EXT_COUNTS[count]}-TRUE"
    return f"ENUM-{count}-0-FALSE"


def vectors():
    module = harness.pycrate_module(PREFIX)
    rows = []
    for (count, ext), values in SHAPES.items():
        for value in values:
            rows.append(
                {
                    "type": type_name(count, ext),
                    "input": {"value": value, "count": count, "extensible": ext},
                }
            )
    py = harness.pycrate_encode(module, [(row["type"], f"m-{row['input']['value'] + 1}") for row in rows])
    otp = harness.otp_encode(PREFIX, [(row["type"], f"'m-{row['input']['value'] + 1}'") for row in rows])
    return harness.merge(rows, py, otp, {})
