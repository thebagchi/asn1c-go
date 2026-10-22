"""Oracle vectors for an extension additions bitmap of more than 64 bits (X.691 19.7, 19.8).

19.8 invokes 11.9 with a length determinant that is a normally small length. For
n > 64 bits 11.9.3.4 writes a bit 1 and then n as an unconstrained length with the
procedures of 11.9.3.5 to 11.9.3.8.4 (fragments of 16K bits from 16K), followed by
the bits. That is an unconstrained BIT STRING of the same n bits behind one leading
1 bit. The bitmap rows are derived this way from the answer of both oracles for a
BIT STRING (testing.asn1, type Bits):
  APER: the unconstrained length is octet-aligned (11.9.3.6), so the leading bit
        is followed by 7 zero pad bits: octet 80, then the BIT STRING octets.
  UPER: no pad: the bit 1, then the BIT STRING bits, padded to an octet at the end.
The derivation is checked on a SEQUENCE: ExtBig (testing.asn1) has 70
additions; both oracles encode it, and the Go test writes the same values with
EncodeAdditions and the open types. The bitmap rows with 65, 70 and 100 bits are
the small cases of the derivation, which the current code answers too.

Bit rule of the bitmap, the one of fragment.py: bit i is bit (7 - i mod 8) of the
octet (i div 8) * 7 + 3 mod 256. The sequence rows set the additions named in
"present".

Output: the key "additions" of testing.json (sections bitmap and sequence). Where pycrate differs on the
bitmap of 70 additions (APER: the known padding fault; UPER too, with a wrong length
for n > 64: it writes 1 where X.691 11.9.3.4 and 11.9.3.6 want the length 70), the
row takes OTP, which matches the clauses, and keeps both answers.

Run: testing.py runs this module; see harness.py

Revisions:
  - 2026-10-19 14:53: initial creation
  - 2026-10-20 00:04: read testing.asn1 through harness.py; return the vectors, write no file
  - 2026-10-20 00:43: every row keeps the answers of both oracles, py and er for each variant, with
    expected and derived (see harness.py)
"""

import fragment
import harness

KIND = "additions"
PREFIX = "Additions"

COUNTS = [65, 70, 100, 16384, 16385, 32768, 65536, 65537, 70000]
PRESENT = [[0], [69], [0, 63, 64, 69], list(range(70)), list(range(0, 70, 3)), [64]]


def uper_bits(count):
    """The number of bits of an unconstrained BIT STRING of count bits in UPER (11.9.3.5 to 11.9.3.8)."""
    total, left = 0, count
    while left >= 16384:
        parts = min(left // 16384, 4)
        total += 8 + parts * 16384
        left -= parts * 16384
    return total + (8 if left < 128 else 16) + left


def shift_one(hexed, count):
    """The bit 1 followed by the bits of hexed (the BIT STRING of count bits), padded to an octet."""
    bits = bin(int(hexed, 16))[2:].zfill(len(hexed) * 4)[: uper_bits(count)]
    bits = "1" + bits
    bits += "0" * (-len(bits) % 8)
    return "%0*x" % (len(bits) // 4, int(bits, 2))


def pattern_bits(present):
    bits = [0] * 70
    for i in present:
        bits[i] = 1
    return bits


def bit_answers():
    module = harness.pycrate_module("Fragments")
    py_in, otp_in = [], []
    for count in COUNTS:
        bits = fragment.bit_octets(count)
        py_in.append(("Bits", (int.from_bytes(bits, "big") >> ((-count) % 8), count)))
        whole = ",".join(str(b) for b in bits[: count // 8])
        if count % 8:
            tail = f"{bits[-1] >> (8 - count % 8)}:{count % 8}"
            whole = whole + ("," if whole else "") + tail
        otp_in.append(("Bits", "<<" + whole + ">>"))
    for present in PRESENT:
        bits = pattern_bits(present)
        py_in.append(("Bits", (int("".join(map(str, bits)), 2), 70)))
        otp_in.append(("Bits", "<<" + ",".join(f"{b}:1" for b in bits) + ">>"))
    py = harness.pycrate_encode(module, py_in)
    otp = harness.otp_encode("Fragments", otp_in)
    patterns = []
    for present, p, o in zip(PRESENT, py[len(COUNTS):], otp[len(COUNTS):]):
        if p != o:
            raise SystemExit(f"oracles disagree on the BIT STRING of {present}")
        patterns.append(p)
    rows = []
    for count, p, o in zip(COUNTS, py, otp):
        if p != o:
            raise SystemExit(f"oracles disagree on a BIT STRING of {count} bits")
        item = {"type": "Additions", "count": count}
        item.update(
            harness.compose(
                None,
                None,
                derived={
                    "aper": "80" + p[0],
                    "uper": shift_one(p[1], count),
                    "how": "X.691 19.8, 11.9.3.4: a 1 bit and the unconstrained BIT STRING of both oracles",
                },
                expected={"aper": "derived", "uper": "derived"},
            )
        )
        rows.append(item)
    return {"rows": rows, "patterns": patterns}


def erl(value):
    parts = ["true" if value["a"] else "false"]
    for i in range(1, 71):
        parts.append("true" if f"x{i}" in value else "asn1_NOVALUE")
    return "{'" + PREFIX + "-ExtBig'," + ",".join(parts) + "}"


def sequence_answers():
    module = harness.pycrate_module(PREFIX)
    values = []
    for present in PRESENT:
        value = {"a": True}
        for i in present:
            value[f"x{i + 1}"] = True
        values.append(value)
    py = []
    for value in values:
        obj = module.ExtBig
        obj.set_val(dict(value))
        py.append((obj.to_aper().hex(), obj.to_uper().hex()))
    otp = harness.otp_encode(PREFIX, [("ExtBig", erl(v)) for v in values])
    rows = []
    for value, p, o in zip(values, py, otp):
        item = {"type": "ExtBig", "value": value}
        item["_pair"] = (p, o)
        rows.append(item)
    return rows


def vectors():
    bitmap = bit_answers()
    sequence = sequence_answers()
    for row, bits, present in zip(sequence, bitmap["patterns"], PRESENT):
        # APER: neither oracle follows 11.9.3.6 for a bitmap of more than 64 bits (OTP writes the
        # length n in a 10-bit field behind the pad, pycrate another form), and UPER of OTP does.
        # Expected APER: ext bit 1, a 1, the flag bit 1, the pad of the aligned length, then the
        # BIT STRING octets of the oracles for the 70 bits, then 01 80 for each present addition.
        derived = "e0" + bits[0] + "0180" * len(present)
        p, o = row.pop("_pair")
        row.update(
            harness.compose(
                p,
                o,
                choose="er",
                clause=(
                    "aper: OTP writes the length of a bitmap of more than 64 bits as a 10-bit field and "
                    "pycrate another form; X.691 11.9.3.4 and 11.9.3.6 want a 1 bit, the pad of the "
                    "octet-aligned length, the length octet and the bits, so the expected octets are "
                    "e0 + the BIT STRING octets of both oracles for the 70 bits + 0180 per present "
                    "addition. uper: OTP taken (matches 11.9.3.4, 11.9.3.6); pycrate differs"
                ),
                derived={
                    "aper": derived,
                    "how": "e0 + the BIT STRING octets of both oracles for the 70 bits + 0180 per present addition",
                },
                expected={"aper": "derived"},
            )
        )
    document = {"bitmap": bitmap["rows"], "sequence": sequence}
    return document
