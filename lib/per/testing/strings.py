"""Oracle vectors for the restricted character string types (X.691 clauses 10.3, 30).

testing.asn1 holds one type for each combination of string kind, SIZE and FROM that both
oracles compile, named Strings-T<number>. testing_pycrate.asn1 holds the combinations that
only pycrate answers, named Strings-P<number>: an extensible FROM (the OTP compiler crashes
in asn1ct_imm:string_num_bits), a one-character FROM (the UPER build of OTP does not compile
it), and a FROM set above U+007F (OTP reads the source as Latin-1 and so reads the set as
two characters). A row of such a type has no OTP answer. The number follows the order in which
build() meets the combinations, and this file does not write ASN.1: it takes the type of a row
by that name. testing.asn1 spells ISO646String as VisibleString (the same type; OTP has no
ISO646String keyword). Both oracles read testing.asn1, and this file asks them for the APER and
UPER octets of every value.

Output: the key "strings" of testing.json. A row holds a value as a list of characters ("chars") or as
a rule ("gen") that the Go test (strings_test.go) and this file apply in the same
way. The answers of a row are in the form of harness.py (hex, or sha256 and octets). The value rules, with M the number of characters
of the alphabet (the FROM set when the row has one) in ascending order:

  all     every character, ascending
  rev     every character, descending
  cycle   character i is alphabet[(i * 31 + 3) mod M], for i below count
  stride  character i is alphabet[(i * step) mod M], for i below count
  pad     count times "a" and then the characters of tail

Pycrate refuses U+007F in an IA5String, so the values of the IA5String rows run over
ia5x (0..126); the rows that hold U+007F have OTP as their only oracle. The
alphabet names are ia5, ia5x, visible, printable, numeric, bmp, universal, ascii,
octets and utf8. A Go string cannot hold a surrogate (U+D800..U+DFFF), so bmp and
universal leave them out. The alphabet of a known-multiplier type is still its
whole range for the width (X.691 30.5.2): the width is set by the type, not by
what Go can hold.

Pycrate keeps a GeneralString, GraphicString, TeletexString or VideotexString as
text and writes ISO 2022 escape sequences for an octet above 0x7F, which is not
the octet string of X.691 30.6.2. A row of those types with an octet above 0x7F
therefore has OTP as its only oracle.

The oracles disagree on some rows. CLAUSES holds the rows that were decided and
the clause that decides; any other disagreement stops the run.

Run: testing.py runs this module; see harness.py. Set STRINGS_CACHE to a file outside the tree to
keep the oracle answers between runs (a key holds the definition of the type and the value).

Revisions:
  - 2026-10-19 12:20: initial creation
  - 2026-10-20 00:09: read testing.asn1 through harness.py, write no ASN.1; drop the extensible FROM, one-character FROM and
    non-ASCII FROM types; return the vectors, write no file
  - 2026-10-20 00:43: restore the rows of the extensible, one-character and non-ASCII FROM types
    (types in testing_pycrate.asn1); every row keeps the answers of both oracles (py, er), expected
    and decided_by
  - 2026-10-21 18:42: type_texts reads a name that fmt_asn1.py padded to line up the ::=
"""

import functools
import hashlib
import json
import os
import sys

import harness
import strings_ref

KIND = "strings"
PREFIX = "Strings"

# kind -> (family, alphabet name). family is "known" for X.691 30.5 and "octet"
# for X.691 30.6.
KINDS = {
    "BMPString": ("known", "bmp"),
    "GeneralString": ("octet", "ascii"),
    "GraphicString": ("octet", "ascii"),
    "IA5String": ("known", "ia5x"),
    "ISO646String": ("known", "visible"),
    "NumericString": ("known", "numeric"),
    "PrintableString": ("known", "printable"),
    "TeletexString": ("octet", "ascii"),
    "T61String": ("octet", "ascii"),
    "UniversalString": ("known", "universal"),
    "UTF8String": ("octet", "utf8"),
    "VideotexString": ("octet", "ascii"),
    "VisibleString": ("known", "visible"),
}
FULL = {"IA5String": "ia5"}
RANGE_KINDS = ("IA5String", "VisibleString", "PrintableString")
BYTE_KINDS = ("GeneralString", "GraphicString", "TeletexString", "T61String", "VideotexString")

PRINTABLE = " '()+,-./0123456789:=?ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
UTF8_MIX = [0x41, 0x7A, 0xE9, 0x20AC, 0x4E2D, 0x1F600, 0x10FFFF, 0x7FF, 0x800, 0xFFFD, 0x10000, 0x80]
SURROGATES = range(0xD800, 0xE000)

# Rows of a disagreement that were decided: row id -> (oracle that the clause
# supports, clause text).
CLAUSES = {}
DECIDED = []
FAULT_ROWS = []
CHECKS = []


@functools.lru_cache(maxsize=None)
def alphabet(name):
    if name == "ia5":
        return list(range(0, 128))
    if name == "ia5x":
        return list(range(0, 127))
    if name == "visible":
        return list(range(32, 127))
    if name == "printable":
        return sorted(ord(c) for c in PRINTABLE)
    if name == "numeric":
        return sorted(ord(c) for c in " 0123456789")
    if name == "bmp":
        return [c for c in range(0, 0x10000) if c not in SURROGATES]
    if name == "universal":
        return [c for c in range(0, 0x110000) if c not in SURROGATES]
    if name == "ascii":
        return list(range(0, 128))
    if name == "octets":
        return list(range(0, 256))
    if name == "utf8":
        return sorted(UTF8_MIX)
    raise SystemExit("unknown alphabet " + name)


def resolve(spec, frm):
    """Return the characters of a value spec as a list of code points."""
    if "chars" in spec:
        return list(spec["chars"])
    gen = spec["gen"]
    if gen["rule"] == "pad":
        return [ord("a")] * gen["count"] + list(gen["tail"])
    base = alphabet(gen["over"])
    if frm is not None:
        keep = set(frm)
        base = [c for c in base if c in keep]
    rule = gen["rule"]
    if rule == "all":
        return base
    if rule == "rev":
        return base[::-1]
    count = gen["count"]
    if rule == "cycle":
        return [base[(i * 31 + 3) % len(base)] for i in range(count)]
    if rule == "stride":
        return [base[(i * gen["step"]) % len(base)] for i in range(count)]
    if rule == "pad":
        return [ord("a")] * count + list(gen["tail"])
    raise SystemExit("unknown rule " + rule)


def pycrate_only(kind, frm, frm_ext):
    """True for a type that OTP cannot compile or reads wrongly: it goes to testing_pycrate.asn1."""
    if frm_ext:
        return True
    if frm is not None and len(set(frm)) == 1:
        return True
    return frm is not None and any(code > 0x7F for code in frm)


class Registry:
    def __init__(self):
        self.types = {}
        self.order = []
        self.rows = []
        self.seen = set()
        self.counts = {}

    def type_of(self, kind, size, frm, frm_ext):
        key = (kind, json.dumps(size, sort_keys=True), tuple(sorted(set(frm))) if frm else None, frm_ext)
        if key not in self.types:
            letter = "P" if pycrate_only(kind, frm, frm_ext) else "T"
            self.counts[letter] = self.counts.get(letter, 0) + 1
            self.types[key] = f"{letter}{self.counts[letter]}"
            self.order.append((self.types[key], kind, size, frm, frm_ext))
        return self.types[key]

    def add(self, kind, size, frm, spec, label, frm_ext=False, py_only=False):
        ident = f"{kind}/{label}"
        if ident in self.seen:
            return None
        self.seen.add(ident)
        name = self.type_of(kind, size, frm, frm_ext)
        chars = resolve(spec, frm)
        row = {
            "id": ident,
            "type": name,
            "kind": kind,
            "size": size,
        }
        if frm is not None:
            row["from"] = sorted(set(frm))
            if frm_ext:
                row["from_ext"] = True
        if "chars" in spec:
            row["chars"] = chars
        else:
            row["gen"] = spec["gen"]
            row["length"] = len(chars)
        row["_chars"] = chars
        row["_py_only"] = py_only
        self.rows.append(row)
        return row


def fixed(n, ext=False):
    return {"lb": n, "ub": n, "ext": ext}


def span(lb, ub, ext=False):
    return {"lb": lb, "ub": ub, "ext": ext}


def semi(lb):
    return {"lb": lb, "ub": None, "ext": False}


def size_label(size):
    if size is None:
        return "nosize"
    lb, ub, ext = size["lb"], size["ub"], size["ext"]
    text = f"{lb}..MAX" if ub is None else (f"{lb}" if lb == ub else f"{lb}..{ub}")
    return "size" + text + ("ext" if ext else "")


def cyc(over, count):
    return {"gen": {"rule": "cycle", "over": over, "count": count}}


def chars(*points):
    return {"chars": list(points)}


def lengths_in(size, extra=()):
    """Lengths in the root of size: both ends and the middle."""
    lb, ub = size["lb"], size["ub"]
    found = {lb, (lb + ub) // 2, ub}
    found.update(extra)
    return sorted(found)


def known_matrix(reg, kind):
    family, over = KINDS[kind]
    big = [16383, 16384, 16385, 32768, 65537]
    plain = [None]
    for n in (1, 2, 3, 4, 5, 8, 16):
        plain.append(fixed(n))
    for lb, ub in ((0, 1), (0, 2), (0, 4), (1, 2), (1, 4), (2, 6), (0, 10), (5, 20), (0, 255), (0, 256), (10, 300)):
        plain.append(span(lb, ub))
    plain.append(semi(2))
    plain.append(fixed(3, True))
    plain.append(span(1, 4, True))
    plain.append(span(0, 2, True))
    for size in plain:
        if size is None:
            lens = [0, 1, 2, 3, 8, 16, 17]
        elif size["ub"] is None:
            lens = [2, 3, 20]
        elif size["ext"]:
            lens = lengths_in(size, (size["ub"] + 1, size["ub"] + 17))
            if size["lb"] > 0:
                lens.append(0)
        else:
            lens = lengths_in(size)
        for n in sorted(set(lens)):
            reg.add(kind, size, None, cyc(over, n), f"{size_label(size)}/n{n}")
    # Fragmentation (X.691 11.9.3.8): unconstrained, a large upper bound, and a
    # fixed length at and above 64K.
    for size in (None, span(0, 100000), semi(1), span(1, 70000, True)):
        for n in big:
            if over in ("bmp", "universal") and size is not None and size["ext"] and n >= 16384:
                # Both oracles are wrong on these rows: pycrate counts the fragments in
                # octets and OTP leaves out the extension bit. Neither answer can be used.
                continue
            reg.add(kind, size, None, cyc(over, n), f"{size_label(size)}/n{n}")
    for n in (65535, 65536):
        reg.add(kind, fixed(n), None, cyc(over, n), f"{size_label(fixed(n))}/n{n}")
    reg.add(kind, span(0, 65535), None, cyc(over, 16384), "size0..65535/n16384")
    reg.add(kind, span(0, 65536), None, cyc(over, 16385), "size0..65536/n16385")


def sweep(reg, kind):
    """Every character of the alphabet, for the known-multiplier kinds."""
    family, over = KINDS[kind]
    base = alphabet(over)
    if over == "universal":
        spec = {"gen": {"rule": "stride", "over": over, "count": 11000, "step": 97}}
        label = "stride97"
    else:
        spec = {"gen": {"rule": "all", "over": over}}
        label = "all"
    n = len(base)
    for size in (None, fixed(n), span(1, n), span(0, n + 10, True)) if over != "universal" else (None, span(0, 100000)):
        reg.add(kind, size, None, spec, f"{size_label(size)}/{label}")
    if over != "universal":
        reg.add(kind, None, None, {"gen": {"rule": "rev", "over": over}}, "nosize/rev")
    if kind == "IA5String":
        full = {"gen": {"rule": "all", "over": "ia5"}}
        for size in (None, fixed(128), span(1, 128), span(0, 138, True)):
            reg.add(kind, size, None, full, f"{size_label(size)}/all128")
        reg.add(kind, None, None, {"gen": {"rule": "rev", "over": "ia5"}}, "nosize/rev128")
        reg.add(kind, None, None, chars(0x7F), "nosize/del")
    if over in ("bmp", "universal"):
        planes = [0x0, 0x7F, 0x80, 0xFF, 0x100, 0x7FF, 0x800, 0xD7FF, 0xE000, 0xFFFD, 0xFFFF]
        if over == "universal":
            planes += [0x10000, 0x1F600, 0x10FFFF, 0x20000, 0xE0001]
        reg.add(kind, None, None, chars(*planes), "nosize/planes")
        reg.add(kind, span(1, len(planes)), None, chars(*planes), "size1..N/planes")
        reg.add(kind, fixed(len(planes)), None, chars(*planes), "sizeN/planes")
        for code in planes:
            reg.add(kind, None, None, chars(code), f"nosize/one{code:X}")


def octet_matrix(reg, kind):
    family, over = KINDS[kind]
    plain = [
        (None, [0, 1, 2, 3, 8, 16, 17]),
        (fixed(3), [3]),
        (fixed(2), [2]),
        (fixed(1), [1]),
        (span(1, 4), [1, 4]),
        (span(0, 10), [0, 5, 10]),
        (semi(2), [2, 5]),
        (fixed(3, True), [3, 5]),
        (span(1, 4, True), [1, 4, 6]),
        (span(0, 100000), [16384]),
        (span(0, 100000), [65537]),
    ]
    for size, lens in plain:
        for n in lens:
            reg.add(kind, size, None, cyc(over, n), f"{size_label(size)}/n{n}")
    for n in (16383, 16384, 16385, 32768, 49152, 65537):
        reg.add(kind, None, None, cyc(over, n), f"nosize/n{n}")
    if kind in BYTE_KINDS:
        reg.add(kind, None, None, {"gen": {"rule": "all", "over": "ascii"}}, "nosize/ascii128")
        reg.add(kind, None, None, {"gen": {"rule": "all", "over": "octets"}}, "nosize/octets256")
        reg.add(kind, fixed(3), None, chars(0xE9, 0xFF, 0x80), "size3/high3")
        reg.add(kind, None, None, cyc("octets", 16385), "nosize/highn16385")
    else:
        reg.add(kind, None, None, chars(0x4E2D, 0x6587), "nosize/cjk")
        reg.add(kind, None, None, chars(0x1F600), "nosize/emoji")
        reg.add(kind, fixed(3), None, chars(0xE9, 0x4E2D, 0x1F600), "size3/mix3")
        reg.add(kind, None, None, {"gen": {"rule": "all", "over": "utf8"}}, "nosize/mix")
        # A fragment of 16K cuts the two-octet character in the middle.
        for count in (16383, 16384, 32767, 32768):
            reg.add(kind, None, None, {"gen": {"rule": "pad", "count": count, "tail": [0xE9]}}, f"nosize/pad{count}e")
        reg.add(kind, None, None, {"gen": {"rule": "pad", "count": 16383, "tail": [0x1F600]}}, "nosize/pad16383emoji")


def from_sets():
    """Name and code points of the FROM sets of the ASCII-text matrix."""
    rng = lambda lo, hi: list(range(ord(lo) if isinstance(lo, str) else lo, (ord(hi) if isinstance(hi, str) else hi) + 1))
    return [
        ("az", rng("a", "z")),
        ("ACGT", [ord(c) for c in "ACGT"]),
        ("single", [ord("a")]),
        ("n2", [ord(c) for c in "ab"]),
        ("n3", [ord(c) for c in "abc"]),
        ("n4", [ord(c) for c in "abcd"]),
        ("n5", [ord(c) for c in "abcde"]),
        ("n15", rng("a", "o")),
        ("n16", rng("a", "p")),
        ("n17", rng("a", "q")),
        ("digits", rng("0", "9")),
        ("upper", rng("A", "Z")),
        ("mixed", rng("a", "z") + [ord("0"), ord("1")]),
        ("scatter", [ord(c) for c in "ZQ!#-~7"]),
    ]


def control_sets():
    """Sets whose largest value fits in the width (the characters keep their values)."""
    return [
        ("c1to7", list(range(1, 8))),
        ("c0to7", list(range(0, 8))),
        ("c1to8", list(range(1, 9))),
        ("c0to15", list(range(0, 16))),
        ("c1to15", list(range(1, 16))),
        ("c0to16", list(range(0, 17))),
        ("c0to4", list(range(0, 5))),
        ("c0to3and9", [0, 1, 2, 3, 9]),
        ("c0to3andF", [0, 1, 2, 3, 15]),
        ("c1to3", [1, 2, 3]),
        ("c0and1", [0, 1]),
        ("c0to127", list(range(0, 128))),
        ("c1to127", list(range(1, 128))),
    ]


def from_rows(reg, kind, sets, sizes=None):
    family, over = KINDS[kind]
    over = FULL.get(kind, over)
    base = set(alphabet(over))
    for name, points in sets:
        if not set(points) <= base:
            continue
        # A line break inside a literal ends the line for the OTP tokenizer, and
        # only IA5String, VisibleString and PrintableString take the range form
        # in pycrate.
        if kind not in RANGE_KINDS and set(points) & {9, 10, 11, 12, 13}:
            continue
        n = len(points)
        specs = [("all", {"gen": {"rule": "all", "over": over}}), ("rev", {"gen": {"rule": "rev", "over": over}})]
        # all and rev run over the alphabet; resolve() restricts them to the FROM set.
        specs.append(("cycle1", cyc(over, 1)))
        specs.append(("cycle2n1", cyc(over, 2 * n + 1)))
        for label, spec in specs:
            reg.add(kind, None, points, spec, f"from{name}/nosize/{label}")
        for size, lens in sizes or ():
            for ln in lens:
                reg.add(kind, size, points, cyc(over, ln), f"from{name}/{size_label(size)}/n{ln}")


def from_combos(reg):
    """FROM combined with SIZE (fixed, range, extensible)."""
    combos = [
        (fixed(3), [3]),
        (fixed(1), [1]),
        (fixed(5), [5]),
        (fixed(9), [9]),
        (span(1, 4), [1, 2, 4]),
        (span(0, 3), [0, 3]),
        (span(2, 20), [2, 20]),
        (fixed(3, True), [3, 0, 8]),
        (span(1, 4, True), [1, 4, 5, 30]),
    ]
    for kind in ("IA5String", "VisibleString", "PrintableString", "BMPString", "UniversalString", "ISO646String"):
        sets = [s for s in from_sets() if s[0] in ("az", "ACGT", "single", "n2", "n5", "n17", "digits")]
        sets += [s for s in control_sets() if s[0] in ("c1to7", "c0to3and9", "c0to127")]
        from_rows(reg, kind, sets, combos)
    for kind in ("NumericString",):
        numsets = [
            ("n0123", [ord(c) for c in "0123"]),
            ("odd", [ord(c) for c in "13579"]),
            ("digits", list(range(48, 58))),
            ("space", [32]),
            ("withspace", [32, 48, 49]),
            ("all11", list(range(48, 58)) + [32]),
            ("nine", list(range(48, 57))),
        ]
        from_rows(reg, kind, numsets, combos)


def ext_from_rows(reg):
    """An extensible FROM is not PER-visible (X.691 10.3.11): the parent kind."""
    cases = [
        ("IA5String", "az", list(range(97, 123)), None, [3, 20]),
        ("IA5String", "ACGT", [ord(c) for c in "ACGT"], span(1, 4), [1, 4]),
        ("IA5String", "single", [97], fixed(3), [3]),
        ("PrintableString", "digits", list(range(48, 58)), span(1, 4), [2]),
        ("NumericString", "digits", list(range(48, 58)), fixed(4), [4]),
        ("VisibleString", "n5", [ord(c) for c in "abcde"], None, [5]),
        ("BMPString", "az", list(range(97, 123)), span(0, 5), [4]),
        ("UniversalString", "az", list(range(97, 123)), None, [3]),
        ("IA5String", "az", list(range(97, 123)), span(1, 4, True), [2, 6]),
    ]
    for kind, name, points, size, lens in cases:
        over = KINDS[kind][1]
        for ln in lens:
            reg.add(kind, size, points, cyc(over, ln), f"fromext{name}/{size_label(size)}/n{ln}", frm_ext=True)
    # A value with characters outside the set: legal, because the set is not visible.
    for kind in ("IA5String", "BMPString", "PrintableString"):
        reg.add(kind, None, [ord("a"), ord("b")], chars(ord("Z"), ord("a"), ord("b"), ord("A")), "fromextab/nosize/outside", frm_ext=True)


def nonascii_rows(reg):
    """FROM sets written with characters above 0x7F: pycrate only."""
    cases = [
        ("BMPString", "bmp4", [0xE9, 0xE0, 0xFC, 0x4E2D]),
        ("BMPString", "latin", [0xE0, 0xE1, 0xE2, 0xE3, 0xE4]),
        ("UniversalString", "emoji3", [0x1F600, 0x1F601, 0x1F602]),
        ("UniversalString", "mixed5", [0x61, 0xE9, 0x4E2D, 0x1F600, 0x10FFFF]),
    ]
    for kind, name, points in cases:
        over = KINDS[kind][1]
        for label, spec in (("all", {"gen": {"rule": "all", "over": over}}), ("cycle9", cyc(over, 9))):
            reg.add(kind, None, points, spec, f"from{name}/nosize/{label}", py_only=True)
        reg.add(kind, fixed(3), points, cyc(over, 3), f"from{name}/size3/n3", py_only=True)


def build():
    reg = Registry()
    for kind, (family, over) in KINDS.items():
        if family == "known":
            known_matrix(reg, kind)
            sweep(reg, kind)
        else:
            octet_matrix(reg, kind)
    for kind in ("IA5String", "VisibleString", "PrintableString", "BMPString", "UniversalString", "ISO646String"):
        from_rows(reg, kind, from_sets() + control_sets(), [])
    from_combos(reg)
    ext_from_rows(reg)
    nonascii_rows(reg)
    return reg


def reference(row, aligned, policy=None):
    """The reading of the clauses (strings_ref.py) for one row and variant."""
    kind = row["kind"]
    chars_ = row["_chars"]
    if KINDS[kind][0] == "octet":
        if kind == "UTF8String":
            data = "".join(chr(c) for c in chars_).encode("utf-8")
        else:
            data = bytes(chars_)
        return strings_ref.encode_octets(data, aligned)
    over = KINDS[kind][1]
    if over == "bmp":
        base = (0, 0xFFFF, 0x10000)
    elif over == "universal":
        base = (0, 0xFFFFFFFF, 2**32)
    else:
        base = alphabet(over)
    frm = row.get("from")
    if row.get("from_ext"):
        frm = None
    return strings_ref.encode_known(base, row["size"], frm, chars_, aligned, policy)


POLICIES = [
    {},
    {"keep": "renumber"},
    {"keep": "parent"},
    {"align": "var"},
    {"frag": "octets"},
    {"ext": "big"},
    {"keep": "renumber", "align": "var"},
    {"keep": "parent", "align": "var"},
    {"keep": "renumber", "frag": "octets"},
    {"align": "var", "frag": "octets"},
]

FAULTS = {
    "keep=renumber": "30.5.4 a): the characters keep their values when the largest fits in b bits; the oracle numbers them from 0",
    "keep=parent": "30.5.4 b): numbering is from zero over the permitted alphabet; the oracle numbers over the whole type",
    "align=var": "30.5.7: the field is octet-aligned only when aub * b >= 16; the oracle aligns whenever a length determinant is present",
    "frag=octets": "11.9.3.8.1, 11.9.3.8.2 d): a fragment of m * 16K is counted in characters; the oracle counts octets",
    "ext=big": "30.4, 10.3.9: a size constraint with an extension marker adds the bit also when ub >= 64K; the oracle omits it",
}


def explain(row, aligned, wrong_hex):
    """Name the reading of the clauses that reproduces a wrong answer."""
    if KINDS[row["kind"]][0] != "known":
        return "unexplained (octet type)"
    if row["kind"] in ("BMPString", "UniversalString") and len(row["_chars"]) > 16384:
        return FAULTS["frag=octets"] + "; the remainder after the first fragment is also wrong"
    for policy in POLICIES[1:]:
        try:
            if reference(row, aligned, policy) == wrong_hex:
                return "; ".join(FAULTS[f"{k}={v}"] for k, v in policy.items())
        except (ValueError, KeyError, IndexError):
            continue
    return "unexplained"


def pycrate_value(row):
    chars_ = row["_chars"]
    return "".join(chr(c) for c in chars_)


def otp_value(row):
    chars_ = row["_chars"]
    kind = row["kind"]
    if row.get("from"):
        # OTP reads a character of a FROM-constrained type as an integer.
        return "[" + ",".join(str(c) for c in chars_) + "]"
    if kind == "BMPString":
        return "[" + ",".join("{0,0,%d,%d}" % (c >> 8, c & 0xFF) for c in chars_) + "]"
    if kind == "UniversalString":
        return "[" + ",".join("{%d,%d,%d,%d}" % (c >> 24, (c >> 16) & 0xFF, (c >> 8) & 0xFF, c & 0xFF) for c in chars_) + "]"
    if kind == "UTF8String":
        data = "".join(chr(c) for c in chars_).encode("utf-8")
        return "<<" + ",".join(str(b) for b in data) + ">>"
    return "[" + ",".join(str(c) for c in chars_) + "]"


CACHE = os.environ.get("STRINGS_CACHE")
_STORE = {}
if CACHE and os.path.exists(CACHE):
    with open(CACHE) as _handle:
        _STORE = json.load(_handle)


def cache_key(*parts):
    return hashlib.sha1("|".join(parts).encode()).hexdigest()


def save_cache():
    if CACHE:
        with open(CACHE, "w") as handle:
            json.dump(_STORE, handle)


def pycrate_answers(module, rows, defs):
    """Return {"aper": hex, "uper": hex} or {"error": text} or None, per row."""
    out = []
    for row in rows:
        if row["kind"] in BYTE_KINDS and any(c > 0x7F for c in row["_chars"]):
            out.append(None)
            continue
        value = pycrate_value(row)

        def compute(row=row, value=value):
            obj = getattr(module, row["type"])
            try:
                obj.set_val(value)
                return {"aper": obj.to_aper().hex(), "uper": obj.to_uper().hex()}
            except Exception as err:  # a refusal by pycrate is an answer: none
                return {"error": str(err)[:100]}

        key = cache_key("pycrate", defs[row["type"]], value)
        if key not in _STORE:
            _STORE[key] = compute()
        out.append(_STORE[key])
    return out


def otp_asked(rows):
    """Return [{"aper": hex, "uper": hex}] or [{"error": text}] from OTP, per row."""
    raw = harness.otp_raw(PREFIX, [(row["type"], otp_value(row)) for row in rows])
    out = []
    for index in range(len(rows)):
        item = {}
        for variant in ("aper", "uper"):
            answer = raw[variant][index]
            if answer.startswith("error"):
                item = {"error": answer[:100]}
                break
            item[variant] = answer
        out.append(item)
    return out


def otp_answers(rows, defs):
    """The answers of OTP per row; None for a row of a type that only pycrate answers (P<n>)."""
    asked = [row for row in rows if row["type"].startswith("T")]
    answers = iter(_otp_answers(asked, defs))
    return [next(answers) if row["type"].startswith("T") else None for row in rows]


def _otp_answers(rows, defs):
    keys = [cache_key("otp", defs[row["type"]], otp_value(row)) for row in rows]
    todo = [i for i, key in enumerate(keys) if key not in _STORE]
    if todo:
        fresh = otp_asked([rows[i] for i in todo])
        for index, answer in zip(todo, fresh):
            _STORE[keys[index]] = answer
    return [_STORE[key] for key in keys]


def type_texts():
    """Return {short type name: the line of testing.asn1 that defines it}, for the cache keys."""
    texts = {}
    for path in (harness.ASN1, harness.ASN1_PYCRATE):
        for line in harness.read_text(path).split("\n"):
            if line.startswith(PREFIX + "-T") or line.startswith(PREFIX + "-P"):
                # fmt_asn1.py pads the name to line up the ::= of a block.
                name, _, text = line.partition("::=")
                texts[name.rstrip()[len(PREFIX) + 1 :]] = text.removeprefix(" ")
    return texts


def finish(reg):
    defs = type_texts()
    missing = sorted(set(entry[0] for entry in reg.order) - set(defs))
    if missing:
        raise SystemExit("testing.asn1 and testing_pycrate.asn1 have no definition of " + ", ".join(missing[:5]))
    module = harness.pycrate_module(PREFIX)
    py = pycrate_answers(module, reg.rows, defs)
    otp = otp_answers(reg.rows, defs)
    save_cache()

    out_rows = []
    disagreements = []
    refused = []
    for row, p, o in zip(reg.rows, py, otp):
        item = {k: v for k, v in row.items() if not k.startswith("_")}
        answers = {"aper": {}, "uper": {}}
        for oracle, ans in (("pycrate", p), ("otp", o)):
            if ans is None or "error" in ans:
                continue
            for variant in ("aper", "uper"):
                if variant in ans:
                    answers[variant][oracle] = ans[variant]
        if not answers["aper"] or not answers["uper"]:
            refused.append((row["id"], p, o))
            continue
        chosen = {}
        expected = {}
        derived = {}
        faults = {}
        for variant in ("aper", "uper"):
            distinct = set(answers[variant].values())
            if len(distinct) == 1:
                chosen[variant] = next(iter(distinct))
                mine = reference(row, variant == "aper")
                if mine != chosen[variant]:
                    if len(answers[variant]) == 1:
                        # The only oracle that answered is wrong: the octets of the clause (the
                        # reading in strings_ref.py) are the expected ones, kept as derived.
                        only = next(iter(answers[variant]))
                        expected[variant] = "derived"
                        derived[variant] = mine
                        faults[variant] = (
                            "the only oracle that answers ("
                            + only
                            + ") differs from the clause: "
                            + explain(row, variant == "aper", chosen[variant])
                        )
                        FAULT_ROWS.append((only, faults[variant], row["id"] + "#" + variant))
                        chosen[variant] = mine
                    else:
                        CHECKS.append((row["id"] + "#" + variant, chosen[variant], mine))
                        chosen[variant] = None
                continue
            mine = reference(row, variant == "aper")
            winners = [name for name, hexed in answers[variant].items() if hexed == mine]
            if len(winners) != 1:
                disagreements.append((row["id"] + "#" + variant, dict(answers[variant], reference=mine)))
                chosen[variant] = None
                continue
            chosen[variant] = answers[variant][winners[0]]
            expected[variant] = "py" if winners[0] == "pycrate" else "er"
            DECIDED.append((row, variant, winners[0], answers[variant]))
            wrong = [name for name in answers[variant] if name != winners[0]][0]
            fault = explain(row, variant == "aper", answers[variant][wrong])
            faults[variant] = fault
            FAULT_ROWS.append((wrong, fault, row["id"] + "#" + variant))
        if None in chosen.values():
            continue
        item.update(
            harness.compose(
                _pair(p, "pycrate cannot answer: ISO 2022 escapes above 0x7F"),
                _pair(o, "OTP cannot compile the type (testing_pycrate.asn1)"),
                expected=expected,
                clause=("; ".join(f"{variant}: {text}" for variant, text in faults.items()) or None),
                derived=(dict(derived, how="X.691 30.5, the reading of strings_ref.py") if derived else None),
            )
        )
        out_rows.append(item)
    return out_rows, disagreements, refused


def _pair(answer, note):
    """The (aper, uper) of an answer dict for harness.compose; None for a missing answer."""
    if answer is None:
        return ("error " + note, "error " + note)
    if "error" in answer:
        return ("error " + answer["error"], "error " + answer["error"])
    return (answer["aper"], answer["uper"])


def vectors():
    reg = build()
    rows, disagreements, refused = finish(reg)
    for key, answer, mine in CHECKS:
        print("CHECK", key, answer[:50], mine[:50], file=sys.stderr)
    for key, answers in disagreements:
        print("DISAGREE", key, {k: v[:70] for k, v in answers.items()}, file=sys.stderr)
    for key, py, ot in refused:
        print("NOANSWER", key, str(py)[:100], str(ot)[:100], file=sys.stderr)
    if disagreements or refused or CHECKS:
        sys.exit(1)
    faults = {}
    for faulty, fault, ident in FAULT_ROWS:
        entry = faults.setdefault((faulty, fault), {"count": 0, "examples": []})
        entry["count"] += 1
        if len(entry["examples"]) < 3:
            entry["examples"].append(ident)
    summary = [
        {"faulty": k[0], "fault": k[1], "count": v["count"], "examples": v["examples"]}
        for k, v in sorted(faults.items(), key=lambda kv: -kv[1]["count"])
    ]
    return {"faults": summary, "strings": rows}
