"""Oracle vectors for EncodeIRI, EncodeRelativeIRI and their decoders
(X.691 26, 27).

Neither oracle has OID-IRI or RELATIVE-OID-IRI as a usable type (pycrate lists
the keywords but has no class; OTP does not compile them). X.691 clauses 26 and
27 take the contents octets of the BER encoding (X.690 8.21, 8.22: the UTF-8 of
the value's text), place them behind a length determinant as a semi-constrained
octet count (11.9). That is the encoding clause 30.5 and 11.9 give an
unconstrained UTF8String, so both oracles answer for a UTF8String of the same
text (testing.asn1, type Text). Row "kind" is "iri" or "relative_iri"; the
octets are the same for both. OTP takes a UTF8String as a binary of UTF-8
octets (a list is read as one octet per element). Output: the key "iri" of testing.json.

Run: testing.py runs this module; see harness.py

Revisions:
  - 2026-10-19 11:43: initial creation
  - 2026-10-20 00:02: read testing.asn1 through harness.py; return the vectors, write no file
  - 2026-10-20 00:43: every row keeps the answers of both oracles, py and er for each variant, with
    expected and derived (see harness.py)
"""

import harness

KIND = "iri"
PREFIX = "Iri"

IRIS = [
    "/ISO/Registration_Authority/19785.CBEFF",
    "/Joint-ISO-ITU-T/3",
    "/Ä/ü",
    "/ISO/日本語",
    "/ISO/\U0001f600",
    "/ISO/" + "a" * 127,
    "/ISO/" + "a" * 128,
    "/ISO/" + "a" * 16378,
    "/ISO/" + "a" * 16379,
    "/ISO/" + "a" * 16380,
    "/ISO/" + "a" * 20000,
    "/ISO/" + "a" * 70000,
    "/ISO/" + "ä" * 9000,
]

RELATIVE_IRIS = [
    "Registration_Authority/19785",
    "19785.CBEFF",
    "ü/Ä",
    "a" * 20000,
]

CLAUSES = {}


def vectors():
    module = harness.pycrate_module(PREFIX)
    rows = []
    for kind, texts in (("iri", IRIS), ("relative_iri", RELATIVE_IRIS)):
        for text in texts:
            rows.append({"type": "Text", "kind": kind, "value": text})

    py = harness.pycrate_encode(module, [("Text", r["value"]) for r in rows])
    otp = harness.otp_encode(
        PREFIX,
        [("Text", "<<" + ",".join(str(b) for b in r["value"].encode("utf-8")) + ">>") for r in rows],
    )
    out = harness.merge(rows, py, otp, CLAUSES)
    return {"iri": out}

