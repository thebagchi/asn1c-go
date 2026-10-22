"""Oracle vectors for EncodeNamedBitString (X.680 22.7, X.691 16.2 and 16.3).

Types: testing.asn1, all with the NamedBitList {a(0), b(1), c(2), d(5),
e(9)}. Output: the key "namedbits" of testing.json. A row has the untrimmed value ("bits", a string
of 0 and 1) and the value that is transmitted ("transmitted", or null when the
type refuses the value).

What each oracle does with 16.2 and 16.3:
  - OTP 29.1.1 removes and adds trailing 0 bits itself. It is given the named
    bit set as an atom list ([a, e]) when every 1 bit has a name, and the
    untrimmed bit string (<<1:1, ...>>) otherwise. A second run gives it the
    untrimmed bit string of every row whose length is a multiple of eight
    (OTP refuses a bit string of other lengths with a badmatch in
    bs_drop_trailing_zeroes). That run is a cross-check that is kept in
    "otp_bitstring" and is not an oracle answer: OTP 29.1.1 fails with a
    badmatch when the bit string must be padded up to the SIZE lower bound.
  - pycrate 0.8.1 does NOT trim or pad: BIT STRING with a NamedBitList and the
    value (0, 1) gives a 1 bit string. It is given the transmitted value, which
    this file computes with transmitted() from the two clauses. That is a
    change of the value, not of the octets: every octet comes from pycrate.

A row is refused when the transmitted value has more bits than the upper bound
of a type with no extension marker (X.691 16.3: no size satisfies the
constraint). A type with the marker sends it outside the root (16.6).

Run: testing.py runs this module; see harness.py

Revisions:
  - 2026-10-19 13:35: initial creation
  - 2026-10-20 00:05: read testing.asn1 through harness.py; return the vectors, write no file
  - 2026-10-20 00:43: every row keeps the answers of both oracles, py and er for each variant, with
    expected and derived (see harness.py)
"""

import harness

KIND = "namedbits"
PREFIX = "Namedbits"

NAMES = {0: "a", 1: "b", 2: "c", 5: "d", 9: "e"}

# type: (lb, ub, extensible); None is no bound.
TYPES = {
    "N0": (None, None, False),
    "N1": (8, 8, False),
    "N2": (4, 12, False),
    "N3": (0, 20, False),
    "N4": (2, 7, True),
    "N5": (16, 32, False),
}


def bits_of(length, *ones):
    """Return a bit string of length with the 1 bits at the places in ones."""
    out = ["0"] * length
    for place in ones:
        out[place] = "1"
    return "".join(out)


def transmitted(bits, lb, ub, ext):
    """Apply X.691 16.2 and 16.3: the smallest size that carries the value and
    satisfies the (effective) size constraint. None means no size does."""
    kept = bits.rstrip("0")
    if ub is not None and len(kept) > ub:
        return kept if ext else None
    if lb is not None and len(kept) < lb:
        kept = kept.ljust(lb, "0")
    return kept


def values():
    rows = []
    zeros = [bits_of(n) for n in (0, 1, 8, 20)]
    singles = []
    for place in (0, 5, 9):
        for length in (place + 1, place + 4, 16, 24):
            if length > place:
                singles.append(bits_of(length, place))
    mixed = [
        bits_of(11, 0, 9),
        bits_of(11, 1, 2),
        bits_of(11, 0, 1, 2, 5, 9),
        bits_of(33, 9),
        bits_of(16, 0, 5),
    ]
    # The last 1 bit lies beyond the upper bound of some types; bits 10, 12,
    # 20 and 40 have no name, so OTP gets the raw bit string (length 8k).
    beyond = [
        bits_of(16, 10),
        bits_of(16, 12),
        bits_of(24, 20),
        bits_of(40, 31),
        bits_of(40, 39),
        bits_of(8, 7),
        bits_of(16, 7),
    ]
    for kind in TYPES:
        for bits in zeros + singles + mixed + beyond:
            rows.append((kind, bits))
    return rows


def named_set(bits):
    """The atom list of the 1 bits, or None when a 1 bit has no name."""
    ones = [i for i, c in enumerate(bits) if c == "1"]
    if any(i not in NAMES for i in ones):
        return None
    return "[" + ",".join(NAMES[i] for i in ones) + "]"


def raw(bits):
    return "<<" + ",".join(c + ":1" for c in bits) + ">>" if bits else "<<>>"


def pycrate_answer(module, kind, bits):
    obj = getattr(module, kind)
    try:
        obj.set_val((int(bits, 2) if bits else 0, len(bits)))
        return (obj.to_aper().hex(), obj.to_uper().hex())
    except Exception:
        return None


def vectors():
    module = harness.pycrate_module(PREFIX)
    rows = values()
    plan = []
    for kind, bits in rows:
        lb, ub, ext = TYPES[kind]
        plan.append(transmitted(bits, lb, ub, ext))

    # pycrate: fed the transmitted value; a refused row is fed its trimmed value
    # and must fail on the size constraint.
    py = []
    for (kind, bits), sent in zip(rows, plan):
        py.append(pycrate_answer(module, kind, sent if sent is not None else bits.rstrip("0")))

    # OTP: the untrimmed value, as named bits where it can be.
    otp_terms = []
    for kind, bits in rows:
        otp_terms.append((kind, named_set(bits) or raw(bits)))
    otp = harness.otp_encode(PREFIX, otp_terms)

    # OTP cross-check with the untrimmed bit string (whole octets only).
    cross_at = [i for i, (_, bits) in enumerate(rows) if len(bits) % 8 == 0]
    cross = harness.otp_encode(PREFIX, [(rows[i][0], raw(rows[i][1])) for i in cross_at])
    cross_by = dict(zip(cross_at, cross))

    out = []
    for index, ((kind, bits), sent) in enumerate(zip(rows, plan)):
        lb, ub, ext = TYPES[kind]
        item = {
            "type": kind,
            "lb": lb,
            "ub": ub,
            "ext": ext,
            "bits": bits,
            "transmitted": sent,
        }
        p = py[index]
        o_aper, o_uper = otp[index]
        o_ok = not o_aper.startswith("error") and not o_uper.startswith("error")
        if sent is None:
            if p is not None or o_ok:
                raise SystemExit(f"{kind} {bits}: refused by the clause, answered by pycrate={p} otp={otp[index]}")
            item.update(
                harness.compose(
                    ("error refused by X.691 16.3", "error refused by X.691 16.3"),
                    ("error refused by X.691 16.3", "error refused by X.691 16.3"),
                )
            )
        else:
            if p is None or not o_ok:
                raise SystemExit(f"{kind} {bits}: oracle refused a valid value: pycrate={p} otp={otp[index]}")
            if p != (o_aper, o_uper):
                raise SystemExit(f"{kind} {bits}: disagree pycrate={p} otp={otp[index]}")
            item.update(harness.compose(p, (o_aper, o_uper)))
        if index in cross_by:
            c_aper, c_uper = cross_by[index]
            if c_aper.startswith("error") or c_uper.startswith("error"):
                item["otp_bitstring"] = "refused" if sent is None else "error"
            else:
                item["otp_bitstring"] = "agree" if (c_aper, c_uper) == (item["aper"]["py"], item["uper"]["py"]) else "differ"
                if item["otp_bitstring"] == "differ":
                    raise SystemExit(f"{kind} {bits}: OTP bit string run differs: {cross_by[index]} vs {item['aper']}")
        out.append(item)
    return {"namedbits": out}
