"""Oracle vectors for the held tests of review P29-3.

Three types of testing.asn1, each a row:

- Held-Bits16: a BOOLEAN, then BIT STRING (SIZE (16)). X.691 16.9: a fixed size of 16 bits
  or fewer has no length and is not octet-aligned, so in APER the bits follow the BOOLEAN bit.
- Held-Octets2: a BOOLEAN, then OCTET STRING (SIZE (2)). X.691 17.6: a fixed size of two
  octets or fewer is not octet-aligned either.
- Held-From: IA5String (FROM ("ACGT")). X.691 30.5: four characters need B = 2 bits in both
  variants, and the largest value 0x54 does not fit 2 bits, so each character is its index
  in the sorted set: A 0, C 1, G 2, T 3.

pycrate 0.8.1 and Erlang/OTP 29.1.1 both encode each row in APER and UPER. When they differ,
decide() names the clause and the oracle that follows it; any other difference stops the run.
Output: the key "held" of testing.json; a row is {type, input, aper, uper, ...} in the form of
harness.py.

Run: testing.py runs this module; see harness.py

Revisions:
  - 2026-10-21 18:06: initial creation (review P29-3)
"""

import harness

KIND = "held"
PREFIX = "Held"

BITS = 0xA5C3
BIT_COUNT = 16
OCTETS = bytes([0xA5, 0xC3])
TEXT = "GATTACA"

# (type, input of the Go test, pycrate value, Erlang value)
ROWS = [
    (
        "Bits16",
        {"bits": "a5c3", "length": BIT_COUNT},
        {"b": True, "s": (BITS, BIT_COUNT)},
        "{'Held-Bits16',true,<<16#A5C3:16>>}",
    ),
    (
        "Octets2",
        {"octets": "a5c3"},
        {"b": True, "s": OCTETS},
        "{'Held-Octets2',true,<<16#A5,16#C3>>}",
    ),
    (
        "From",
        {"text": TEXT},
        TEXT,
        '"' + TEXT + '"',
    ),
]

def decide(row):
    """Decide a row where the oracles differ, or return None to stop the run."""
    return None


def vectors():
    module = harness.pycrate_module(PREFIX)
    rows = [{"type": kind, "input": given} for kind, given, _, _ in ROWS]
    py = harness.pycrate_encode(module, [(kind, value) for kind, _, value, _ in ROWS])
    otp = harness.otp_encode(PREFIX, [(kind, value) for kind, _, _, value in ROWS])
    return harness.merge(rows, py, otp, decide)
