"""Oracle vectors for EncodeBitString and DecodeBitString (X.691 16, 11.9).

One type of testing.asn1 for each shape: BITSTRING-<lb>-<ub>-<TRUE or FALSE> (NULL for no
bound; (lb, NULL) is SIZE (lb..MAX); TRUE when the SIZE has the extension marker). The value
of a row is the alternating bit string 0, 1, 0, 1, ... of its length. pycrate 0.8.1 and
Erlang/OTP 29.1.1 both encode every value in APER and UPER. The run stops when they differ,
except for the rows of the two faults below, where CLAUSES takes the oracle that follows the
clause. Output: the key "bit_string" of testing.json; a row is {type, input {length, lb, ub, extensible},
aper, uper, ...} in the form of harness.py, with {sha256, octets} for a long answer.

pycrate fault: the fragmentation of a BIT STRING (APER and UPER) is wrong from 16384 bits when
the unconstrained, semi-constrained or extensible path is used. encode_fragbytes() in codecs.py
evaluates buf[off:off+fs>>3] as buf[off:(off+fs)>>3] instead of buf[off:off+(fs>>3)]. The
result is wrong data from 65536 bits (two fragments) and an IndexError from 147456 bits (three
fragments). A constrained SIZE with ub below 65536 does not fragment and is not affected. The
row keeps both answers and takes OTP.

OTP fault: see octet_string.py. For BIT STRING, with 131072 bits and SIZE (0..65536, ...)
OTP gives C4 55 55 ... where the clause gives 80 C4 55 55 ... pycrate is wrong on the same
rows, so the four rows of this fault (131072, 262144, 524288 and 1048576 bits with the bounds
65536, 131072, 262144 and 524288 and the marker) are not in the list.

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

KIND = "bit_string"
PREFIX = ""

PYCRATE_FRAGMENT_LIMIT = 16384

# (lb, ub, extensible) -> the lengths in bits. None is no bound.
SHAPES = {
    (None, None, False): [
        5, 1, 2, 4, 8, 16, 32, 64, 128, 255, 256, 512, 1024, 2048, 4096, 8192, 16384, 32768, 65536,
        0, 131072, 262144, 524288, 1048576
    ],
    (0, 10, False): [
        5
    ],
    (10, None, False): [
        10
    ],
    (0, None, False): [
        1, 2, 4, 8, 16, 32, 64, 128, 255, 256, 512, 1024, 2048, 4096, 8192, 16384, 32768, 65536, 0,
        131072, 262144, 524288, 1048576
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
        255, 256
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
    (1, 1, False): [
        1
    ],
    (8, 8, False): [
        8
    ],
    (16, 16, False): [
        16
    ],
    (32, 32, False): [
        32
    ],
    (64, 64, False): [
        64
    ],
    (128, 128, False): [
        128
    ],
    (1, None, False): [
        1, 8, 64, 256
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
        16, 0, 4, 8
    ],
    (0, 16, True): [
        32, 0, 8, 16
    ],
    (0, 32, True): [
        64, 16, 32
    ],
    (0, 64, True): [
        128, 32, 64
    ],
    (0, 128, True): [
        255, 256, 64, 128
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
    (1, 1, True): [
        1, 2
    ],
    (8, 8, True): [
        8, 16
    ],
    (16, 16, True): [
        16, 32
    ],
    (32, 32, True): [
        32, 64
    ],
    (64, 64, True): [
        64, 128
    ],
    (128, 128, True): [
        128, 256
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
    (16, 64, True): [
        16, 64, 15, 65
    ],
}


def type_name(lb, ub, ext):
    lb_text = "NULL" if lb is None else str(lb)
    ub_text = "NULL" if ub is None else str(ub)
    return f"BITSTRING-{lb_text}-{ub_text}-{'TRUE' if ext else 'FALSE'}"


def pycrate_bits(length):
    """The pycrate value (integer, length) of the alternating bit string 0101..."""
    full, rest = divmod(length, 8)
    value = int.from_bytes(bytes([0x55]) * full, "big") << rest
    if rest:
        value |= 0x55 >> (8 - rest)
    return (value, length)


def erlang_bits(length):
    """The Erlang expression of the same value."""
    full, rest = divmod(length, 8)
    if not rest:
        return f"binary:copy(<<85>>,{full})"
    return f"B=binary:copy(<<85>>,{full}),<<B/bitstring,(85 bsr {8 - rest}):{rest}>>"


def clause(row):
    """Decide a row where pycrate is wrong: the fragmentation fault, OTP taken; None for any other."""
    if row["input"]["length"] >= PYCRATE_FRAGMENT_LIMIT:
        return (
            "otp",
            "pycrate fragments a BIT STRING wrongly from 16384 bits (encode_fragbytes); X.691 11.9.3.8, OTP taken",
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
    py = harness.pycrate_encode(module, [(row["type"], pycrate_bits(row["input"]["length"])) for row in rows])
    otp = harness.otp_encode(PREFIX, [(row["type"], erlang_bits(row["input"]["length"])) for row in rows])
    return harness.merge(rows, py, otp, clause)
