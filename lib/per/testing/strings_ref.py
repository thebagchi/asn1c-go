"""A reading of X.691 clauses 10.3, 11.5, 11.9 and 30 for the restricted character strings.

This is not an oracle. strings.py uses it only to choose between the answers of
pycrate and OTP when they differ, and to check the rows on which they agree. The
vector octets always come from an oracle: when this reading matches neither
answer, the row stays undecided.

The reading, in the order of the clauses:

  30.5.2   N characters in the effective permitted alphabet; B the smallest
           integer with 2^B >= N; B2 the smallest power of 2 with B2 >= B; each
           character takes B2 bits in ALIGNED and B bits in UNALIGNED
  30.5.4   the characters keep their value v when the largest value is at most
           2^b - 1, else they are numbered 0.. in canonical order
  30.4     an extensible type adds one bit: 0 inside the root, else the encoding
           is as if there were no effective size constraint
  30.5.6   alb = aub < 64K: no length; the field is octet-aligned (ALIGNED) when
           aub * b > 16
  30.5.7   otherwise 11.9 adds a length and the field is octet-aligned (ALIGNED)
           when aub * b >= 16
  11.9.3.3 / 11.9.4.1  a length with ub < 64K is a constrained whole number
  11.5.7   the ALIGNED constrained whole number: range <= 255 a bit-field, 256 one
           octet, up to 64K two octets (octet-aligned)
  11.9.3.5-8 / 11.9.4.2  any other length is the unconstrained form with the
           fragments of 16K units (in characters for a known-multiplier type)
  30.6     the other types: an octet string behind an unconstrained length

Revisions:
  - 2026-10-19 12:40: initial creation
"""

K16 = 16384
K64 = 65536


class Bits:
    def __init__(self):
        self.out = bytearray()
        self.acc = 0
        self.pending = 0
        self.count = 0

    def add(self, value, width):
        if not width:
            return
        self.acc = (self.acc << width) | (value & ((1 << width) - 1))
        self.pending += width
        self.count += width
        while self.pending >= 8:
            self.pending -= 8
            self.out.append((self.acc >> self.pending) & 0xFF)
        self.acc &= (1 << self.pending) - 1

    def align(self):
        self.add(0, (-self.count) % 8)

    def hex(self):
        data = bytes(self.out)
        if self.pending:
            data += bytes([(self.acc << (8 - self.pending)) & 0xFF])
        if not data:
            return "00"
        return data.hex()


def width_of(count):
    """B and B2 of 30.5.2 for an alphabet of count characters."""
    low = 0
    while (1 << low) < count:
        low += 1
    high = 1
    while high < low:
        high *= 2
    return low, high


def char_width(count, aligned):
    low, high = width_of(count)
    return high if aligned else low


def size_range(size):
    """Return (alb, aub, ext) from a size dict; aub None when unbounded."""
    if size is None:
        return 0, None, False
    return size["lb"], size["ub"], size["ext"]


def constrained(bits, value, lb, ub, aligned):
    """11.5: a constrained whole number."""
    rng = ub - lb + 1
    if rng == 1:
        return
    n = value - lb
    if not aligned:
        bits.add(n, (rng - 1).bit_length())
    elif rng <= 255:
        bits.add(n, (rng - 1).bit_length())
    elif rng == 256:
        bits.align()
        bits.add(n, 8)
    elif rng <= K64:
        bits.align()
        bits.add(n, 16)
    else:
        raise ValueError("range above 64K")


def length_and_field(bits, units, write_units, alb, aub, aligned, field_aligned, frag_bytes=1):
    """11.9: a length determinant and the field. write_units(start, stop) writes units."""
    n = len(units)
    if aub is not None and aub < K64:
        if aub == alb:
            if n and aligned and field_aligned:
                bits.align()
            write_units(0, n)
            return
        constrained(bits, n, alb, aub, aligned)
        if n:
            if aligned and field_aligned:
                bits.align()
            write_units(0, n)
        return
    start = 0
    left = n
    # frag_bytes > 1 is a reading in which the length and the fragments count
    # octets once the value reaches 16K characters: the fault of pycrate with
    # the two-octet and four-octet characters.
    unit = frag_bytes if (frag_bytes > 1 and n >= K16) else 1
    while True:
        if aligned:
            bits.align()
        count = left * unit
        if count < 128:
            bits.add(count, 8)
            if aligned:
                bits.align()
            write_units(start, start + left)
            return
        if count < K16:
            bits.add(0x8000 | count, 16)
            if aligned:
                bits.align()
            write_units(start, start + left)
            return
        m = min(count // K16, 4)
        bits.add(0xC0 | m, 8)
        if aligned:
            bits.align()
        taken = m * K16 // unit
        write_units(start, start + taken)
        start += taken
        left -= taken


def encode_known(kind_alphabet, size, frm, chars, aligned, policy=None):
    """kind_alphabet: sorted list of the characters of the whole type, or a pair
    (lo, hi, count) for a contiguous alphabet that is too big to list."""
    policy = policy or {}
    bits = Bits()
    alb, aub, ext = size_range(size)
    parent = kind_alphabet if not isinstance(kind_alphabet, tuple) else None
    if frm is not None:
        members = sorted(set(frm))
        count = len(members)
        top = members[-1]
        index = {c: i for i, c in enumerate(members)}
    elif isinstance(kind_alphabet, tuple):
        lo, hi, count = kind_alphabet
        top = hi
        index = None
    else:
        members = kind_alphabet
        count = len(members)
        top = members[-1]
        index = {c: i for i, c in enumerate(members)}
    width = char_width(count, aligned)
    keep = top <= (1 << width) - 1
    if policy.get("keep") == "renumber":
        keep = False

    def code(c):
        if keep:
            return c
        if policy.get("keep") == "parent" and parent is not None:
            return parent.index(c)
        if index is None:
            return c
        return index[c]

    if ext:
        inside = alb <= len(chars) <= aub if aub is not None else len(chars) >= alb
        if not (policy.get("ext") == "big" and aub is not None and aub >= K64):
            bits.add(0 if inside else 1, 1)
        if not inside:
            alb, aub = 0, None

    def write_units(start, stop):
        for c in chars[start:stop]:
            bits.add(code(c), width)

    if aub is not None and aub == alb and aub < K64:
        field_aligned = aub * width > 16
    else:
        field_aligned = aub is None or aub * width >= 16
    if policy.get("align") == "var" and not (aub is not None and aub == alb and not ext):
        field_aligned = True
    frag = 1
    if policy.get("frag") == "octets":
        frag = 4 if width == 32 else (2 if width == 16 else 1)
    length_and_field(bits, chars, write_units, alb, aub, aligned, field_aligned, frag)
    return bits.hex()


def encode_octets(octets, aligned):
    """30.6: unconstrained length in octets, then the octets."""
    bits = Bits()

    def write_units(start, stop):
        for b in octets[start:stop]:
            bits.add(b, 8)

    length_and_field(bits, octets, write_units, 0, None, aligned, True)
    return bits.hex()
