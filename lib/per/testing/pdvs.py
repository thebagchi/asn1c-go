"""Oracle vectors for EMBEDDED PDV, EXTERNAL, CHARACTER STRING and INSTANCE OF (X.691 28, 29, 31;
X.681 Annex C).

The types are in testing.asn1 (pycrate 0.8.1 and Erlang/OTP 29.1.1 both read them). OTP, and
only OTP, also reads the type INSTANCE OF TYPE-IDENTIFIER itself (Pdvs-Inst of testing_otp.asn1);
pycrate cannot compile it, so the answer of the associated type InstSeq (X.681 C.7) is the
expected one, as for the other three kinds. Per row the JSON keeps the answers of both oracles
(py, er) and the expected one, in the form of harness.py.

What the oracles encode, and what the expected octets are:
  - The expected octets come from the type that the clause names, which is a SEQUENCE in
    testing.asn1: PdvSeq (X.691 28.3), CsSeq (31.3), ExtSeq (29.1), InstSeq (X.681 C.7). pycrate
    and OTP must agree on it, or the run stops.
  - OTP's built-in EMBEDDED PDV, CHARACTER STRING and EXTERNAL give the same octets
    as the SEQUENCE on every row. The row keeps native_otp: true.
  - pycrate's built-in EMBEDDED PDV, CHARACTER STRING and EXTERNAL do not: pycrate writes the
    OPTIONAL bit of data-value-descriptor that X.691 28.3 and 31.3 remove, and its EXTERNAL is
    the identification form of X.680 37.5, not the SEQUENCE of X.691 29.1. The clause decides:
    the row keeps the pycrate answer under native_pycrate and is not used.
  - Neither oracle uses the constraint of X.691 28.1 a) and 31.1 a): the types PdvFixed,
    PdvSyntax and CsFixed (identification constrained to one alternative) encode the same
    octets as the general case in OTP (checked: "constrained"). The predefined rows are therefore
    the OCTET STRING of the data value (X.691 28.2, 31.2), type Predefined.
  - pycrate fails on a value of 16K octets or more (known fault, X.691 11.9.3.8); OTP answers.
  - OTP 29.1.1 and pycrate agree on every other row.

Run: testing.py runs this module; see harness.py

Revisions:
  - 2026-10-19 15:13: initial creation
  - 2026-10-20 00:07: read testing.asn1 through harness.py; return the vectors, write no file
  - 2026-10-20 00:43: restore the native INSTANCE OF answer of OTP (Pdvs-Inst in testing_otp.asn1);
    every row keeps the answers of both oracles (py, er)
"""

import hashlib

import harness

KIND = "pdvs"
PREFIX = "Pdvs"

LONG = 16384

# Object identifiers and integers of the rows. 2.999.3 has a second arc of 40 or more under the
# first arc 2 (X.690 8.19.4); 840 and 113549 need several octets.
OID_A = [1, 3, 6, 1, 4, 1, 99, 1]
OID_B = [2, 1, 1]
OID_C = [1, 2, 840, 113549, 1, 1, 1]
OID_D = [2, 999, 3]
OID_E = [0, 0, 13, 35, 3, 2]
SMALL = (True, 77)
SMALL_OTHER = (False, 0)

IDENTIFICATIONS = [
    {"alt": "syntaxes", "abstract": OID_A, "transfer": OID_B},
    {"alt": "syntaxes", "abstract": OID_D, "transfer": OID_C},
    {"alt": "syntax", "oid": OID_A},
    {"alt": "syntax", "oid": OID_C},
    {"alt": "presentation-context-id", "id": 0},
    {"alt": "presentation-context-id", "id": 1},
    {"alt": "presentation-context-id", "id": 127},
    {"alt": "presentation-context-id", "id": 128},
    {"alt": "presentation-context-id", "id": -1},
    {"alt": "presentation-context-id", "id": 70000},
    {"alt": "presentation-context-id", "id": 9223372036854775807},
    {"alt": "presentation-context-id", "id": -9223372036854775808},
    {"alt": "context-negotiation", "id": 5, "oid": OID_E},
    {"alt": "context-negotiation", "id": 300, "oid": OID_D},
    {"alt": "transfer-syntax", "oid": OID_B},
    {"alt": "transfer-syntax", "oid": OID_C},
    {"alt": "fixed"},
]
# The identifications that EXTERNAL can hold, X.691 29.4 Table 1.
EXTERNAL_IDENTIFICATIONS = [
    {"alt": "syntax", "oid": OID_A},
    {"alt": "syntax", "oid": OID_D},
    {"alt": "presentation-context-id", "id": 0},
    {"alt": "presentation-context-id", "id": 300000},
    {"alt": "presentation-context-id", "id": -1},
    {"alt": "context-negotiation", "id": 5, "oid": OID_E},
    {"alt": "context-negotiation", "id": 128, "oid": OID_C},
]

SHORT = {"hex": "010203"}
EMPTY = {"hex": ""}


def data(count):
    return {"count": count}


def octets(spec):
    """The octets of a data spec: hex, or component i = (i * 7 + 3) mod 256."""
    if "hex" in spec:
        return bytes.fromhex(spec["hex"])
    return bytes((i * 7 + 3) % 256 for i in range(spec["count"]))


def bit_pattern(count):
    """Bit i of an arbitrary BIT STRING of count bits is 1 when (i * 7 + 3) mod 5 < 2."""
    return [1 if (i * 7 + 3) % 5 < 2 else 0 for i in range(count)]


def bit_integer(count):
    value = 0
    for bit in bit_pattern(count):
        value = value * 2 + bit
    return value


def erl_oid(oid):
    return "{" + ",".join(str(arc) for arc in oid) + "}"


def erl_bin(spec):
    if "count" in spec:
        return f"list_to_binary([(I*7+3) rem 256 || I <- lists:seq(0,{spec['count'] - 1})])" if spec["count"] else "<<>>"
    return "<<" + ",".join(str(b) for b in octets(spec)) + ">>"


def erl_text(text):
    return "[" + ",".join(str(ord(c)) for c in text) + "]"


def erl_bits(count):
    return f"<<{bit_integer(count)}:{count}>>" if count else "<<>>"


def py_ident(ident):
    alt = ident["alt"]
    if alt == "syntaxes":
        return (alt, {"abstract": tuple(ident["abstract"]), "transfer": tuple(ident["transfer"])})
    if alt in ("syntax", "transfer-syntax"):
        return (alt, tuple(ident["oid"]))
    if alt == "presentation-context-id":
        return (alt, ident["id"])
    if alt == "context-negotiation":
        return (alt, {"presentation-context-id": ident["id"], "transfer-syntax": tuple(ident["oid"])})
    return (alt, 0)


def erl_ident(ident, prefix):
    """prefix is the record prefix: Ident, EMBEDDED PDV_identification, CHARACTER STRING_identification."""
    alt = ident["alt"]
    if alt == "syntaxes":
        return f"{{syntaxes,{{'{prefix}_syntaxes',{erl_oid(ident['abstract'])},{erl_oid(ident['transfer'])}}}}}"
    if alt in ("syntax", "transfer-syntax"):
        return f"{{'{alt}',{erl_oid(ident['oid'])}}}"
    if alt == "presentation-context-id":
        return f"{{'presentation-context-id',{ident['id']}}}"
    if alt == "context-negotiation":
        return f"{{'context-negotiation',{{'{prefix}_context-negotiation',{ident['id']},{erl_oid(ident['oid'])}}}}}"
    return "{fixed,'NULL'}"


def references(ident):
    """X.691 29.4 Table 1: (direct-reference, indirect-reference) of an EXTERNAL identification."""
    alt = ident["alt"]
    if alt == "syntax":
        return ident["oid"], None
    if alt == "presentation-context-id":
        return None, ident["id"]
    if alt == "context-negotiation":
        return ident["oid"], ident["id"]
    raise SystemExit(f"Table 1: {alt} cannot occur")


def pdv_rows(kind):
    rows = []
    for ident in IDENTIFICATIONS:
        for spec in (EMPTY, SHORT):
            rows.append({"type": kind, "identification": ident, "data": spec})
    # data value lengths: the 127/128 boundary of the length determinant (11.9.3.3, 11.9.3.5),
    # 300, and the first fragment (11.9.3.8)
    for ident in (IDENTIFICATIONS[2], IDENTIFICATIONS[12], IDENTIFICATIONS[-1]):
        for count in (127, 128, 300, LONG):
            rows.append({"type": kind, "identification": ident, "data": data(count)})
    return rows


def external_rows():
    rows = []
    encodings = [
        {"alt": "single-ASN1-type", "small": list(SMALL)},
        {"alt": "single-ASN1-type", "small": list(SMALL_OTHER)},
        {"alt": "single-ASN1-type", "data": {"hex": "00"}},
        {"alt": "single-ASN1-type", "data": data(300)},
        {"alt": "octet-aligned", "data": EMPTY},
        {"alt": "octet-aligned", "data": SHORT},
        {"alt": "octet-aligned", "data": data(300)},
    ] + [{"alt": "arbitrary", "bits": bits} for bits in (0, 1, 13, 16, 17, 130)]
    for ident in EXTERNAL_IDENTIFICATIONS:
        for encoding in encodings:
            rows.append({"type": "ext", "identification": ident, "descriptor": None, "encoding": encoding})
    for ident in (EXTERNAL_IDENTIFICATIONS[0], EXTERNAL_IDENTIFICATIONS[-1]):
        for encoding in encodings:
            rows.append({"type": "ext", "identification": ident, "descriptor": "Test PDU", "encoding": encoding})
    rows.append(
        {
            "type": "ext",
            "identification": EXTERNAL_IDENTIFICATIONS[2],
            "descriptor": "d" * 130,
            "encoding": encodings[5],
        }
    )
    rows.append(
        {
            "type": "ext",
            "identification": EXTERNAL_IDENTIFICATIONS[3],
            "descriptor": "",
            "encoding": encodings[5],
        }
    )
    rows.append(
        {
            "type": "ext",
            "identification": EXTERNAL_IDENTIFICATIONS[0],
            "descriptor": None,
            "encoding": {"alt": "octet-aligned", "data": data(LONG)},
        }
    )
    return rows


def neither_rows():
    """Octets of the SEQUENCE of 29.1 with neither reference. No value of EXTERNAL has them: 29.4
    gives every identification a reference. DecodeExternal must refuse them."""
    return [
        {"type": "neither", "descriptor": None, "encoding": {"alt": "octet-aligned", "data": EMPTY}},
        {"type": "neither", "descriptor": "Test PDU", "encoding": {"alt": "octet-aligned", "data": SHORT}},
        {"type": "neither", "descriptor": None, "encoding": {"alt": "arbitrary", "bits": 13}},
        {"type": "neither", "descriptor": None, "encoding": {"alt": "single-ASN1-type", "small": list(SMALL)}},
    ]


def instance_rows():
    rows = []
    for tid in (OID_A, [2, 5, 29, 15]):
        for value in (
            {"small": list(SMALL)},
            {"small": list(SMALL_OTHER)},
            {"data": {"hex": "00"}},
            {"data": SHORT},
            {"data": data(127)},
            {"data": data(128)},
            {"data": data(300)},
        ):
            rows.append(dict({"type": "inst", "type_id": tid}, **value))
    rows.append({"type": "inst", "type_id": OID_A, "data": data(LONG)})
    return rows


def predefined_rows():
    return [{"type": "predefined", "data": spec} for spec in (EMPTY, SHORT, data(127), data(128), data(300), data(LONG))]


def inner_octets(row, small):
    """The complete encoding of a payload: Small as the oracles encode it in APER, or raw octets.

    The payload is opaque to the codecs, so the same octets serve APER and UPER rows.
    """
    spec = row.get("data")
    if spec is not None:
        return octets(spec).hex()
    return small[tuple(row["small"])]


def asked(row, small):
    """Return {oracle name: (python value for pycrate, Erlang text for OTP)} per probe type."""
    kind = row["type"]
    probes = {}
    if kind in ("pdv", "cs"):
        seq = "PdvSeq" if kind == "pdv" else "CsSeq"
        native = "Pdv" if kind == "pdv" else "Cs"
        key = "data-value" if kind == "pdv" else "string-value"
        value = octets(row["data"])
        probes[seq] = (
            {"identification": py_ident(row["identification"]), key: value},
            f"{{'{PREFIX}-{seq}',{erl_ident(row['identification'], PREFIX + '-Ident')},{erl_bin(row['data'])}}}",
        )
        prefix = "EMBEDDED PDV" if kind == "pdv" else "CHARACTER STRING"
        probes[native] = (
            {"identification": py_ident(row["identification"]), key: value},
            f"{{'{prefix}',{erl_ident(row['identification'], prefix + '_identification')},{erl_bin(row['data'])}}}",
        )
    elif kind == "predefined":
        probes["Predefined"] = (octets(row["data"]), erl_bin(row["data"]))
    elif kind in ("ext", "neither"):
        direct, indirect = references(row["identification"]) if kind == "ext" else (None, None)
        encoding = row["encoding"]
        if encoding["alt"] == "single-ASN1-type":
            inner = inner_octets(encoding, small)
            encoding["inner"] = inner
            py_enc = ("single-ASN1-type", ("_unk_004", bytes.fromhex(inner)))
            erl_enc = f"{{'single-ASN1-type',<<{','.join(str(b) for b in bytes.fromhex(inner))}>>}}"
        elif encoding["alt"] == "octet-aligned":
            py_enc = ("octet-aligned", octets(encoding["data"]))
            erl_enc = f"{{'octet-aligned',{erl_bin(encoding['data'])}}}"
        else:
            py_enc = ("arbitrary", (bit_integer(encoding["bits"]), encoding["bits"]))
            erl_enc = f"{{arbitrary,{erl_bits(encoding['bits'])}}}"
        py_value = {"encoding": py_enc}
        erl_parts = [erl_oid(direct) if direct else "asn1_NOVALUE", str(indirect) if indirect is not None else "asn1_NOVALUE"]
        if direct:
            py_value["direct-reference"] = tuple(direct)
        if indirect is not None:
            py_value["indirect-reference"] = indirect
        if row["descriptor"] is not None:
            py_value["data-value-descriptor"] = row["descriptor"]
            erl_parts.append(erl_text(row["descriptor"]))
        else:
            erl_parts.append("asn1_NOVALUE")
        probes["ExtSeq"] = (py_value, "{'" + PREFIX + "-ExtSeq'," + ",".join(erl_parts) + "," + erl_enc + "}")
        if kind == "neither":
            return probes
        native_py = None
        if encoding["alt"] == "octet-aligned":
            native_py = {"identification": py_ident(row["identification"]), "data-value": octets(encoding["data"])}
            if row["descriptor"] is not None:
                native_py["data-value-descriptor"] = row["descriptor"]
        probes["Ext"] = (native_py, "{'EXTERNAL'," + ",".join(erl_parts) + "," + erl_enc + "}")
    else:
        inner = inner_octets(row, small)
        if "small" in row:
            row["inner"] = inner
        raw = bytes.fromhex(inner)
        probes["Inst"] = (None, f"{{'INSTANCE OF',{erl_oid(row['type_id'])},<<{','.join(str(b) for b in raw)}>>}}")
        probes["InstSeq"] = (
            {"type-id": tuple(row["type_id"]), "value": ("_unk_004", raw)},
            f"{{'{PREFIX}-InstSeq',{erl_oid(row['type_id'])},<<{','.join(str(b) for b in raw)}>>}}",
        )
    return probes


def pycrate_ask(module, name, value):
    """Return (aper, uper) hex from pycrate, or an "error ..." pair."""
    try:
        obj = getattr(module, name)
        obj.set_val(value)
        return obj.to_aper().hex(), obj.to_uper().hex()
    except Exception as exc:  # pycrate refuses or fails: no answer
        text = "error " + type(exc).__name__
        return text, text


def small_inner(module):
    """The APER encoding of Small for the two values, from both oracles (they must agree)."""
    out = {}
    values = [SMALL, SMALL_OTHER]
    py = [pycrate_ask(module, "Small", {"a": a, "b": b}) for a, b in values]
    otp = harness.otp_encode(
        PREFIX,
        [("Small", f"{{'{PREFIX}-Small',{'true' if a else 'false'},{b}}}") for a, b in values],
    )
    for value, p, o in zip(values, py, otp):
        if p[0] != o[0]:
            raise SystemExit(f"oracles disagree on Small {value}: pycrate={p} otp={o}")
        out[value] = p[0]
    return out


def collect(rows, small):
    """Return, per row, {probe type: (pycrate value, Erlang text)}."""
    return [asked(row, small) for row in rows]


def answers(module, rows, probes):
    """Ask both oracles every probe. Return per row {probe: {"pycrate": (a, u), "otp": (a, u)}}."""
    flat = [(index, name) for index, row in enumerate(probes) for name in row]
    py_rows = [pycrate_ask(module, name, probes[index][name][0]) if probes[index][name][0] is not None else None for index, name in flat]
    otp_main = harness.otp_encode(
        PREFIX,
        [(name, probes[index][name][1]) for index, name in flat],
    )
    result = [dict() for _ in probes]
    for (index, name), pair in zip(flat, otp_main):
        result[index].setdefault(name, {})["otp"] = pair
    for (index, name), pair in zip(flat, py_rows):
        if pair is not None:
            result[index].setdefault(name, {})["pycrate"] = pair
    return result


SEQ_OF = {"pdv": "PdvSeq", "cs": "CsSeq", "ext": "ExtSeq", "neither": "ExtSeq", "inst": "InstSeq", "predefined": "Predefined"}
NATIVE_OF = {"pdv": "Pdv", "cs": "Cs", "ext": "Ext", "inst": "Inst"}
CLAUSE = {
    "pdv": "X.691 28.3, X.680 36.5",
    "cs": "X.691 31.3, X.680 44.5",
    "ext": "X.691 29.1, 29.4 Table 1",
    "neither": "X.691 29.1, 29.4 (a value of the SEQUENCE with no reference: no value of the associated type)",
    "inst": "X.681 C.7, X.691 11.2",
    "predefined": "X.691 28.2, 31.2",
}


def is_long(row):
    spec = row.get("data") or row.get("encoding", {}).get("data")
    return spec is not None and spec.get("count", 0) >= LONG


def merge_row(row, answer):
    """Join the answers of one row into a JSON row."""
    kind = row["type"]
    sequence = answer[SEQ_OF[kind]]
    py, otp = sequence.get("pycrate"), sequence["otp"]
    item = dict(row)
    decisions = []
    if otp[0].startswith("error"):
        raise SystemExit(f"OTP gave no answer for {row}: {otp}")
    if py is None or py[0].startswith("error"):
        if not is_long(row):
            raise SystemExit(f"pycrate gave no answer for {row}: {py}")
        decisions.append("pycrate fails on 16K octets or more (X.691 11.9.3.8); OTP taken")
    elif py != otp:
        raise SystemExit(f"oracles disagree on {SEQ_OF[kind]} {row}: pycrate={py} otp={otp}")
    item["clause"] = CLAUSE[kind]
    native = {}
    if kind in NATIVE_OF:
        name = NATIVE_OF[kind]
        nat_otp = answer[name]["otp"]
        native["otp"] = nat_otp == otp
        if not native["otp"]:
            raise SystemExit(f"OTP built-in {name} differs from {SEQ_OF[kind]} on {row}: {nat_otp} vs {otp}")
        nat_py = answer[name].get("pycrate")
        if nat_py is not None and not nat_py[0].startswith("error"):
            native["pycrate"] = nat_py == py
            if nat_py != py:
                item["native_pycrate"] = {"aper": nat_py[0][:120], "uper": nat_py[1][:120]}
                decisions.append(
                    f"pycrate built-in {name} differs from {SEQ_OF[kind]}; {CLAUSE[kind]} decides, the SEQUENCE is taken"
                )
    if "otp" in native:
        item["native_otp"] = native["otp"]
    if decisions:
        item["decided_by"] = "; ".join(decisions)
    item.update(harness.compose(py, otp, clause=None))
    return item


def constrained(module):
    """Ask OTP the types of X.691 28.1 a) and 31.1 a): it must give the general case."""
    cases = []
    for name, seq, ident, prefix, text in (
        ("PdvFixed", "PdvSeq", {"alt": "fixed"}, "EMBEDDED PDV", "EMBEDDED PDV"),
        ("PdvSyntax", "PdvSeq", {"alt": "syntax", "oid": OID_A}, "EMBEDDED PDV", "EMBEDDED PDV"),
        ("CsFixed", "CsSeq", {"alt": "fixed"}, "CHARACTER STRING", "CHARACTER STRING"),
    ):
        spec = SHORT
        cases.append((name, f"{{'{text}',{erl_ident(ident, prefix + '_identification')},{erl_bin(spec)}}}"))
        cases.append((seq, f"{{'{PREFIX}-{seq}',{erl_ident(ident, PREFIX + '-Ident')},{erl_bin(spec)}}}"))
    out = harness.otp_encode(PREFIX, cases)
    return [
        {
            "type": cases[i][0],
            "general_type": cases[i + 1][0],
            "otp_constrained": out[i][0],
            "otp_general": out[i + 1][0],
            "otp_ignores_constraint": out[i] == out[i + 1],
        }
        for i in range(0, len(cases), 2)
    ]


def vectors():
    module = harness.pycrate_module(PREFIX)
    small = small_inner(module)
    rows = pdv_rows("pdv") + pdv_rows("cs") + external_rows() + neither_rows() + instance_rows() + predefined_rows()
    probes = collect(rows, small)
    results = answers(module, rows, probes)
    items = [merge_row(row, answer) for row, answer in zip(rows, results)]
    sections = {}
    for item in items:
        sections.setdefault(item["type"], []).append(item)
    document = dict(sections)
    document["constrained"] = constrained(module)
    return document
