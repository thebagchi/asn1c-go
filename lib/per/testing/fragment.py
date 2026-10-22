"""Oracle vectors for the fragment terminator of X.691 clause 11.9.3.8.

An unconstrained OCTET STRING, BIT STRING and IA5String, at lengths around the
multiples of 16K. The terminator of 11.9.3.8.3 (a zero length) follows a value
only when its count is a multiple of 16K. The values are generated, so the
JSON keeps a long answer as its sha256 and its length in octets, not
the octets. The Go test makes the same value from the same rule:

  octet i of an OCTET STRING:   (i*7 + 3) mod 256
  bit i of a BIT STRING:        bit (7 - i mod 8) of octet (i div 8) of that rule
  character i of an IA5String:  'a' + (i mod 26)

Both oracles encode each value (testing.asn1; OTP takes an IA5String as a list). A disagreement stops the
run unless CLAUSES decides it. Output: the key "fragment" of testing.json.

Run: testing.py runs this module; see harness.py

Revisions:
  - 2026-10-19 11:50: initial creation
  - 2026-10-20 00:02: read testing.asn1 through harness.py; return the vectors, write no file
  - 2026-10-20 00:43: every row keeps the answers of both oracles, py and er for each variant, with
    expected and derived (see harness.py)
"""

import harness

KIND = "fragment"
PREFIX = "Fragments"

LENGTHS = [0, 1, 16383, 16384, 16385, 32768, 32769, 49152, 65535, 65536, 65537, 70000]

CLAUSES = {}


def octet(i):
    return (i * 7 + 3) % 256


def bit_octets(count):
    octets = bytearray(octet(i) for i in range((count + 7) // 8))
    if count % 8:
        octets[-1] &= (0xFF << (8 - count % 8)) & 0xFF
    return bytes(octets)


def text(count):
    return "".join(chr(ord("a") + i % 26) for i in range(count))


def vectors():
    module = harness.pycrate_module(PREFIX)
    rows = []
    py_in = []
    otp_in = []
    for count in LENGTHS:
        data = bytes(octet(i) for i in range(count))
        py_in.append(("Octets", data))
        otp_in.append(("Octets", "<<" + ",".join(str(b) for b in data) + ">>"))
        rows.append({"type": "Octets", "count": count})

        bits = bit_octets(count)
        py_in.append(("Bits", (int.from_bytes(bits, "big") >> ((-count) % 8) if count else 0, count)))
        whole = ",".join(str(b) for b in bits[: count // 8])
        if count % 8:
            tail = f"{bits[-1] >> (8 - count % 8)}:{count % 8}"
            whole = whole + ("," if whole else "") + tail
        otp_in.append(("Bits", "<<" + whole + ">>"))
        rows.append({"type": "Bits", "count": count})

        chars = text(count)
        py_in.append(("Text", chars))
        otp_in.append(("Text", "[" + ",".join(str(ord(c)) for c in chars) + "]"))
        rows.append({"type": "Text", "count": count})

    py = harness.pycrate_encode(module, py_in)
    otp = harness.otp_encode(PREFIX, otp_in)

    return {"fragment": harness.merge(rows, py, otp, CLAUSES)}
