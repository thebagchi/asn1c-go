"""Oracle vectors for SEQUENCE, SET, CHOICE, SEQUENCE OF and SET OF (X.691 19 to 23).

The types are in testing.asn1. Both oracles, pycrate 0.8.1 and
Erlang/OTP 29.1.1, read that file and encode every row in APER and UPER. Per row
the JSON keeps the answers of both oracles and the expected one (harness.py).

Rows by section:
  sequence: Opt (every presence pattern of the OPTIONAL and DEFAULT components,
            a DEFAULT equal to its default and not equal), OptSent (the same
            bits with b and d sent, to decode into Opt), Empty, EmptyExt
  extension: Ext1 and Ext2 (extension additions, one addition group)
  set:      Set1, Set2 (canonical order of the tags, X.691 21)
  choice:   Ch1, Ch2, Ch3, Ch5, ChExt1, ChExt2
  seqof:    SeqNo, Seq3, Seq10, SeqExt, Seq70k, SeqBool, SetNo, SetExt at the
            counts of X.691 20 and 11.9.3.8, component i = (i*7 + 3) mod 256
            (INTEGER) or i mod 3 == 0 (BOOLEAN)

Known oracle faults, and the clause that decides when the two differ:
  - pycrate treats a root component after the second extension marker as an
    extension addition (ExtT1); X.691 19.9 note 2 encodes it before the
    additions. OTP is taken.
  - pycrate pads the APER bitmap of the extension additions to an octet. X.691
    19.7 and 19.8 add the bits after a normally small length (11.9.3.4), and
    11.9.3.4 asks for no alignment. The row keeps both answers and takes OTP.
  - pycrate fails, or answers wrongly, on lists of 16K components or more
    (11.9.3.8, 20.6). The row takes OTP.
  - OTP 29.1.1 reads an addition that follows an addition group from the wrong
    element of the record, so Ext2 puts its group last.
Any other disagreement stops the run.

Run: testing.py runs this module; see harness.py

Revisions:
  - 2026-10-19 14:18: initial creation
  - 2026-10-20 00:03: read testing.asn1 through harness.py; return the vectors, write no file
  - 2026-10-20 00:43: every row keeps the answers of both oracles, py and er for each variant, with
    expected and derived (see harness.py)
"""

import json
import itertools

import harness

KIND = "composites"
PREFIX = "Composites"

LONG = 16384
HEX_LIMIT = 64

# kind of every component: bool, int or str (IA5String). Modes: req, opt, def
# (DEFAULT) and grp (a mandatory member of an extension addition group; it is
# absent when the group is).
SEQUENCES = {
    "Opt": [("a", "bool", "opt"), ("b", "int", "def"), ("c", "str", "opt"), ("d", "bool", "def"), ("e", "int", "req")],
    "OptSent": [("a", "bool", "opt"), ("b", "int", "opt"), ("c", "str", "opt"), ("d", "bool", "opt"), ("e", "int", "req")],
    "Empty": [],
    "EmptyExt": [],
    "Ext1": [("a", "bool", "req"), ("b", "int", "opt"), ("c", "int", "opt")],
    "ExtN": [("a", "bool", "req"), ("n", "null", "opt")],
    "ExtT1": [("a", "bool", "req"), ("b", "int", "opt"), ("c", "int", "opt"), ("t", "int", "req")],
    "Ext2": [
        ("a", "bool", "req"),
        ("b", "int", "opt"),
        ("c", "int", "opt"),
        ("d", "str", "opt"),
        ("g", "bool", "opt"),
        ("e", "bool", "grp"),
        ("f", "int", "opt"),
    ],
    "Set1": [("a", "bool", "req"), ("b", "int", "opt"), ("c", "str", "req")],
    "Set2": [("a", "bool", "req"), ("b", "int", "req"), ("c", "str", "req"), ("d", "bool", "opt"), ("e", "bool", "def")],
    "Set1Seq": [("a", "bool", "req"), ("b", "int", "opt"), ("c", "str", "req")],
    "Set2Seq": [("c", "str", "req"), ("b", "int", "req"), ("e", "bool", "def"), ("a", "bool", "req"), ("d", "bool", "opt")],
}
CHOICES = {
    "Ch1": {"a": "int"},
    "Ch2": {"a": "bool", "b": "int"},
    "Ch3": {"a": "bool", "b": "int", "c": "str"},
    "Ch5": {"a": "bool", "b": "int", "c": "str", "d": "bool", "e": "int"},
    "ChExt1": {"a": "bool", "b": "int", "c": "str"},
    "ChExt2": {"a": "bool", "b": "int", "c": "str", "d": "bool", "e": "int"},
}
LISTS = {"SeqNo": "int", "Seq3": "int", "Seq10": "int", "SeqExt": "int", "Seq70k": "int", "SeqBool": "bool", "SetNo": "int", "SetExt": "int"}

EXTENSIBLE = {"ExtN", "Ext1", "ExtT1", "Ext2", "ChExt1", "ChExt2"}


def erl_scalar(kind, value):
    if kind == "bool":
        return "true" if value else "false"
    if kind == "int":
        return str(value)
    if kind == "null":
        return "'NULL'"
    return "[" + ",".join(str(ord(c)) for c in value) + "]"


def erl_value(name, value):
    if name in SEQUENCES:
        parts = []
        for field, kind, mode in SEQUENCES[name]:
            if field in value:
                parts.append(erl_scalar(kind, value[field]))
            else:
                parts.append("asn1_DEFAULT" if mode == "def" else "asn1_NOVALUE")
        return "{'" + PREFIX + "-" + name + "'" + "".join("," + p for p in parts) + "}"
    if name in CHOICES:
        alt = value["alt"]
        return "{" + alt + "," + erl_scalar(CHOICES[name][alt], value["value"]) + "}"
    return "[" + ",".join(erl_scalar(LISTS[name], v) for v in value) + "]"


def py_value(name, value):
    if name in SEQUENCES:
        return {k: (0 if v is True and k == "n" else v) for k, v in value.items()}
    if name in CHOICES:
        return (value["alt"], value["value"])
    return list(value)


def component(kind, index):
    if kind == "bool":
        return index % 3 == 0
    return (index * 7 + 3) % 256


def rule_list(name, count):
    return [component(LISTS[name], i) for i in range(count)]


def opt_rows():
    rows = []
    grid = itertools.product([None, True, False], [None, 7, 200], [None, "x", "abcdefgh"], [None, True, False])
    for index, (a, b, c, d) in enumerate(grid):
        value = {"e": (index * 37) % 256}
        for field, item in (("a", a), ("b", b), ("c", c), ("d", d)):
            if item is not None:
                value[field] = item
        rows.append(("Opt", value))
        rows.append(("OptSent", value))
    return rows


def ext_rows():
    rows = []
    for index, (a, b, c) in enumerate(itertools.product([True, False], [None, 9], [None, 200])):
        value = {"a": a}
        if b is not None:
            value["b"] = b
        if c is not None:
            value["c"] = c
        rows.append(("Ext1", value))
        rows.append(("ExtT1", dict(value, t=index + 1)))
    grid = itertools.product([None, 33], [None, "hi"], ["none", "e", "ef"], [None, True])
    for index, (c, d, group, g) in enumerate(grid):
        value = {"a": index % 2 == 0}
        if index % 3 == 0:
            value["b"] = 250 - index
        if c is not None:
            value["c"] = c
        if d is not None:
            value["d"] = d
        if group != "none":
            value["e"] = index % 4 == 0
        if group == "ef":
            value["f"] = 100 + index
        if g is not None:
            value["g"] = g
        rows.append(("Ext2", value))
    rows.append(("ExtN", {"a": True}))
    rows.append(("ExtN", {"a": False, "n": True}))
    rows.append(("Empty", {}))
    rows.append(("EmptyExt", {}))
    return rows


def set_rows():
    rows = []
    for index, (a, b, c) in enumerate(itertools.product([True, False], [None, 5], ["a", "hello"])):
        value = {"a": a, "c": c}
        if b is not None:
            value["b"] = b
        rows.append(("Set1", value))
        rows.append(("Set1Seq", value))
    grid = itertools.product([True, False], [None, True, False], [None, True, False])
    for index, (a, d, e) in enumerate(grid):
        value = {"a": a, "b": index * 13 % 256, "c": "abcdefgh"[: index % 8 + 1]}
        if d is not None:
            value["d"] = d
        if e is not None:
            value["e"] = e
        rows.append(("Set2", value))
        rows.append(("Set2Seq", value))
    return rows


def choice_rows():
    rows = []
    samples = {"bool": [True, False], "int": [0, 77, 255], "str": ["x", "abcdefgh"]}
    for name, alts in CHOICES.items():
        for alt, kind in alts.items():
            for value in samples[kind]:
                rows.append((name, {"alt": alt, "value": value}))
    return rows


def list_rows():
    counts = {
        "SeqNo": [0, 1, 3, 10, 11, 127, 128, 16383, 16384, 16385, 32768, 65536, 65537, 70000, 131072, 147457],
        "Seq3": [3],
        "Seq10": [0, 1, 3, 10],
        "SeqExt": [1, 3, 5, 0, 6, 10, 11, 16383, 16384, 16385],
        "Seq70k": [0, 1, 3, 10, 11, 16383, 16384, 16385, 32768, 65536, 65537, 70000],
        "SeqBool": [0, 1, 9, 16383, 16384, 16385, 32768, 65537],
        "SetNo": [0, 1, 3, 11, 16384, 16385, 32768],
        "SetExt": [1, 3, 5, 6, 11, 16384],
    }
    return [(name, count) for name, items in counts.items() for count in items]


def pycrate_answers(module, rows):
    out = []
    for name, value in rows:
        try:
            obj = getattr(module, name)
            obj.set_val(py_value(name, value) if not isinstance(value, int) else rule_list(name, value))
            out.append((obj.to_aper().hex(), obj.to_uper().hex()))
        except Exception as exc:  # pycrate refuses or fails: no answer
            out.append(("error " + type(exc).__name__, "error " + type(exc).__name__))
    return out


def otp_answers(rows):
    lines = []
    for name, value in rows:
        if isinstance(value, int):
            value = rule_list(name, value)
        lines.append((name, erl_value(name, value)))
    return harness.otp_encode(PREFIX, lines)


def decide(name, count, p, o):
    """Return (aper, uper, oracles, agree, decisions) for one row."""
    answers = {}
    if not p[0].startswith("error"):
        answers["pycrate"] = p
    if not o[0].startswith("error"):
        answers["otp"] = o
    if "otp" not in answers:
        raise SystemExit(f"OTP gave no answer for {name} {count}: {o}")
    decisions = []
    final = list(o)
    for slot, variant in enumerate(("aper", "uper")):
        if "pycrate" not in answers:
            decisions.append(f"{variant}: pycrate gave no answer ({p[slot][:60]}); OTP taken, X.691 11.9.3.8 and 20.6")
        elif p[slot] != o[slot]:
            if name == "ExtT1":
                decisions.append(f"{variant}: pycrate sends the trailer as an addition; OTP taken, X.691 19.9 note 2")
            elif name in EXTENSIBLE and variant == "aper":
                decisions.append(f"{variant}: pycrate pads the additions bitmap; OTP taken, X.691 19.7, 19.8, 11.9.3.4")
            elif isinstance(count, int) and count >= LONG:
                decisions.append(f"{variant}: pycrate differs on a list of {count} components; OTP taken, X.691 11.9.3.8, 20.6")
            else:
                raise SystemExit(f"oracles disagree on {name} {count} {variant}: pycrate={p[slot][:80]} otp={o[slot][:80]}")
    agree = "pycrate" in answers and not decisions
    return final[0], final[1], sorted(answers), agree, decisions


def derived(name, count):
    """True for an extensible list beyond the root with 16K components or more.

    OTP 29.1.1 has no fragments for it (if_clause) and pycrate fails on lists of
    16K or more, so no oracle answers. X.691 20.4 writes the extension bit and
    then the length and components of the unconstrained case, so the expected
    octets come from the oracle answer for the same list in SeqNo or SetNo.
    """
    return name in ("SeqExt", "SetExt") and count >= LONG


def prefix_one(hexed):
    """The bits 1 + hexed (UNALIGNED), padded with 0 bits to an octet."""
    bits = "1" + bin(int(hexed, 16))[2:].zfill(len(hexed) * 4)
    bits += "0" * (-len(bits) % 8)
    return "%0*x" % (len(bits) // 4, int(bits, 2))


def build(rows, answers):
    module = harness.pycrate_module(PREFIX)
    asked = [row for row in rows if not (isinstance(row[1], int) and derived(*row))]
    py = pycrate_answers(module, asked)
    otp = otp_answers(asked)
    for row, p, o in zip(asked, py, otp):
        aper, uper, oracles, agree, decisions = decide(row[0], row[1], p, o)
        answers[repr(row)] = (aper, uper, oracles, agree, decisions, p)
    for row in rows:
        if repr(row) not in answers:
            source = {"SeqExt": "SeqNo", "SetExt": "SetNo"}[row[0]]
            aper, uper = answers[repr((source, row[1]))][:2]
            answers[repr(row)] = (
                "80" + aper,
                prefix_one(uper),
                ["otp"],
                False,
                [f"derived from the {source} answer of OTP: bit 1, then the unconstrained case, X.691 20.4"],
                ("", ""),
            )
    out = []
    for row in rows:
        name, value = row
        aper, uper, oracles, agree, decisions, p = answers[repr(row)]
        item = {"type": name}
        if isinstance(value, int):
            item["count"] = value
        else:
            item["value"] = value
        if decisions and decisions[0].startswith("derived from"):
            item.update(
                harness.compose(
                    None,
                    None,
                    derived={"aper": aper, "uper": uper, "how": decisions[0]},
                    expected={"aper": "derived", "uper": "derived"},
                )
            )
        else:
            item.update(harness.compose(p, (aper, uper), choose="er", clause="; ".join(decisions) or None))
        out.append(item)
    return out


def sorted_sets(rows):
    """Give each SET row the expected octets of the SEQUENCE in sorted order.

    Both oracles keep the preamble bits of a SET in textual order, and a row keeps their
    answers. X.691 21 encodes the sorted elements "as if it had been declared a sequence
    type", so the bits are in sorted order (user decision 2026-10-19). The expected octets
    are the expected octets for SetNSeq, declared in that order with the same tags; the row
    keeps them as derived.
    """
    seqs = {(r["type"], json.dumps(r["value"], sort_keys=True)): r for r in rows if r["type"].endswith("Seq")}
    out = []
    for row in rows:
        if row["type"].endswith("Seq"):
            continue
        twin = seqs[(row["type"] + "Seq", json.dumps(row["value"], sort_keys=True))]
        row["derived"] = {
            "aper": harness.expected(twin, "aper"),
            "uper": harness.expected(twin, "uper"),
            "how": "X.691 21: SET encoded as a SEQUENCE in sorted order; user decision 2026-10-19; octets from "
            + row["type"]
            + "Seq",
        }
        row["expected"] = {"aper": "derived", "uper": "derived"}
        row["decided_by"] = row["derived"]["how"]
        out.append(row)
    return out


def vectors():
    answers = {}
    document = {
        "sequence": build(opt_rows() + ext_rows()[-2:], answers),
        "extension": build(ext_rows()[:-2], answers),
        "set": sorted_sets(build(set_rows(), answers)),
        "choice": build(choice_rows(), answers),
        "seqof": build(list_rows(), answers),
    }
    return document

