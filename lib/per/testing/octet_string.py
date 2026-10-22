"""Oracle vectors for EncodeOctetString and DecodeOctetString (X.691 17, 11.9).

One type of testing.asn1 for each shape: OCTETSTRING-<lb>-<ub>-<TRUE or FALSE> (NULL for no
bound; (lb, NULL) is SIZE (lb..MAX); TRUE when the SIZE has the extension marker). The value
of a row is the pattern 0x00, 0x01, ... 0xFF, 0x00, ... of its length. pycrate 0.8.1 and
Erlang/OTP 29.1.1 both encode every value in APER and UPER, and the run stops when they differ.
Output: the key "octet_string" of testing.json; a row is {type, input {length, lb, ub, extensible},
aper, uper, ...} in the form of harness.py, with {sha256, octets} for a long answer.

OTP fault (asn1 5.0.21.1, still there in OTP 29.1.1): for an extensible SIZE, when the value is
longer than the upper bound and the length needs fragments (16384 octets or more), OTP leaves
out the extension bit and writes the encoding of the unconstrained case. For 131072 octets
with SIZE (0..65536, ...) the clause gives 80 C4 00 01 ... and OTP gives C4 00 01 ... The
rows of this fault, from 16384 octets with the bound 8192 up to 1048576 octets with the bound
524288, keep both answers and take pycrate, which writes the extension bit. pycrate 0.8.1 has
no fault for OCTET STRING.

Run: testing.py runs this module; see harness.py

Revisions:
  - 2026-09-22 06:43: initial creation
  - 2026-10-20 00:14: read the types from testing.asn1 and ask both oracles for every value (the lists of
    the pycrate run and the OTP run are one list); one row for each value instead of a row for each variant; return the
    vectors, write no file
  - 2026-10-20 00:43: every row keeps the answers of both oracles, py and er for each variant, with
    expected and derived (see harness.py)
"""

import harness

KIND = "octet_string"
PREFIX = ""

FRAGMENT = 16384

# (lb, ub, extensible) -> the lengths in octets. None is no bound.
SHAPES = {
    (None, None, False): [
        5, 1, 2, 4, 8, 16, 32, 64, 128, 256, 512, 1024, 2048, 4096, 8192, 16384, 32768, 65536,
        131072, 262144, 524288, 1048576, 0
    ],
    (0, 10, False): [
        5
    ],
    (10, None, False): [
        10
    ],
    (0, None, False): [
        1, 2, 4, 8, 16, 32, 64, 128, 256, 512, 1024, 2048, 4096, 8192, 16384, 32768, 65536, 131072,
        262144, 524288, 1048576, 0
    ],
    (0, 2, False): [
        1
    ],
    (0, 4, False): [
        2
    ],
    (0, 8, False): [
        4, 0
    ],
    (0, 16, False): [
        8
    ],
    (0, 32, False): [
        16
    ],
    (0, 64, False): [
        32
    ],
    (0, 128, False): [
        64, 0
    ],
    (0, 256, False): [
        128
    ],
    (0, 512, False): [
        256
    ],
    (0, 1024, False): [
        512
    ],
    (0, 2048, False): [
        1024
    ],
    (0, 4096, False): [
        2048
    ],
    (0, 8192, False): [
        4096
    ],
    (0, 16384, False): [
        8192
    ],
    (0, 32768, False): [
        16384
    ],
    (0, 65536, False): [
        32768, 0
    ],
    (0, 131072, False): [
        65536
    ],
    (0, 262144, False): [
        131072
    ],
    (0, 524288, False): [
        262144
    ],
    (0, 1048576, False): [
        524288
    ],
    (0, 2097152, False): [
        1048576
    ],
    (0, 0, True): [
        1
    ],
    (0, 1, True): [
        2
    ],
    (0, 2, True): [
        4
    ],
    (0, 4, True): [
        8
    ],
    (0, 8, True): [
        16, 0, 4, 8, 1
    ],
    (0, 16, True): [
        32, 0, 8, 16, 1
    ],
    (0, 32, True): [
        64, 16, 32
    ],
    (0, 64, True): [
        128, 32, 64
    ],
    (0, 128, True): [
        256, 64, 128
    ],
    (0, 256, True): [
        512, 128, 256
    ],
    (0, 512, True): [
        1024, 256, 512
    ],
    (0, 1024, True): [
        2048, 512, 1024
    ],
    (0, 2048, True): [
        4096
    ],
    (0, 4096, True): [
        8192
    ],
    (0, 8192, True): [
        16384
    ],
    (0, 16384, True): [
        32768
    ],
    (0, 32768, True): [
        65536
    ],
    (0, 65536, True): [
        131072
    ],
    (0, 131072, True): [
        262144
    ],
    (0, 262144, True): [
        524288
    ],
    (0, 524288, True): [
        1048576
    ],
    (1, 1, False): [
        1
    ],
    (4, 4, False): [
        4
    ],
    (8, 8, False): [
        8
    ],
    (16, 16, False): [
        16
    ],
    (64, 64, False): [
        64
    ],
    (1, None, False): [
        1, 8, 64, 256
    ],
    (1, 127, False): [
        1, 127, 64
    ],
    (1, 128, False): [
        1, 128, 64
    ],
    (1, 255, False): [
        1, 255, 128
    ],
    (1, 256, False): [
        1, 256, 128
    ],
    (1, 1, True): [
        1, 2
    ],
    (4, 4, True): [
        4, 8
    ],
    (8, 8, True): [
        8, 16
    ],
    (16, 16, True): [
        16, 32
    ],
    (64, 64, True): [
        64, 128
    ],
    (1, 127, True): [
        1, 127, 128
    ],
    (1, 128, True): [
        1, 128, 129
    ],
    (1, 255, True): [
        1, 255, 256
    ],
    (1, 256, True): [
        1, 256, 257
    ],
    (4, 16, False): [
        4, 8, 16, 10
    ],
    (8, 32, False): [
        8, 16, 32, 20
    ],
    (16, 64, False): [
        16, 32, 64, 40
    ],
    (4, 16, True): [
        4, 16, 32, 3, 17
    ],
    (8, 32, True): [
        8, 32, 64, 7, 33
    ],
    (16, 64, True): [
        16, 64, 15, 65
    ],
}


def type_name(lb, ub, ext):
    lb_text = "NULL" if lb is None else str(lb)
    ub_text = "NULL" if ub is None else str(ub)
    return f"OCTETSTRING-{lb_text}-{ub_text}-{'TRUE' if ext else 'FALSE'}"


def octets(length):
    """The value of a row: the pattern 0x00 to 0xFF, repeated, of the given length."""
    pattern = bytes(range(256))
    full, rest = divmod(length, len(pattern))
    return pattern * full + pattern[:rest]


def erlang_octets(length):
    """The Erlang expression of the same value (a list of a million bytes would be a line of megabytes)."""
    full, rest = divmod(length, 256)
    return f"P=list_to_binary(lists:seq(0,255)),<<(binary:copy(P,{full}))/binary,(binary:part(P,0,{rest}))/binary>>"


def clause(row):
    """Decide a row where OTP is wrong: an extensible SIZE, a value above the bound, in fragments."""
    size = row["input"]
    if size["extensible"] and size["ub"] is not None and size["length"] > size["ub"] and size["length"] >= FRAGMENT:
        return (
            "pycrate",
            "OTP leaves out the extension bit of a fragmented value outside the root; X.691 clause 17, pycrate taken",
        )
    return None


def vectors():
    module = harness.pycrate_module(PREFIX)
    rows = []
    for (lb, ub, ext), lengths in SHAPES.items():
        for length in lengths:
            rows.append(
                {
                    "type": type_name(lb, ub, ext),
                    "input": {"length": length, "lb": lb, "ub": ub, "extensible": ext},
                }
            )
    py = harness.pycrate_encode(module, [(row["type"], octets(row["input"]["length"])) for row in rows])
    otp = harness.otp_encode(PREFIX, [(row["type"], erlang_octets(row["input"]["length"])) for row in rows])
    return harness.merge(rows, py, otp, clause)
