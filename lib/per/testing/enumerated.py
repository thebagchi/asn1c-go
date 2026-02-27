#!/usr/bin/env python3

import json
from binascii import hexlify

from pycrate_asn1rt.asnobj_basic import ENUM  # type: ignore
from pycrate_asn1rt.dictobj import ASN1Dict  # type: ignore
from pycrate_asn1rt.setobj import ASN1Set, ASN1RangeInt  # type: ignore


def encode_per(obj, aligned=True):
    if aligned:
        return obj.to_aper()
    else:
        return obj.to_uper()


def make_enum(value, count, extensible=False):
    return {"value": value, "count": count, "extensible": extensible}


def build_enum(count, extensible=False, ext_count=0):
    """Build an ENUM ASN.1 object with `count` root values and `ext_count` extension values.

    Root values are named v0, v1, ..., v(count-1).
    Extension values are named v(count), v(count+1), ..., v(count+ext_count-1).
    """
    obj = ENUM(name="ENUMERATED")
    items = []
    for i in range(count + ext_count):
        items.append((f"v{i}", i))
    obj._cont = ASN1Dict(items)
    root = []
    for i in range(count):
        root.append(f"v{i}")
    obj._root = root
    if extensible:
        ext = []
        for i in range(count, count + ext_count):
            ext.append(f"v{i}")
        obj._ext = ext
    else:
        obj._ext = None
    # _const_ind defines the constrained index range for the root values
    ev = [] if extensible else None
    obj._const_ind = ASN1Set(rv=[], rr=[ASN1RangeInt(lb=0, ub=max(0, count - 1))], ev=ev, er=[])
    obj._const_ind._set_root_bnd()
    return obj


def encode_enumerated(value, count, aligned=True, extensible=False, ext_count=0):
    obj = build_enum(count, extensible, ext_count)
    obj.set_val(f"v{value}")
    return encode_per(obj, aligned)


def main():
    results = []

    cases = [
        # ---- Non-extensible cases ----
        # 2 root values (1 bit)
        make_enum(0, 2, False),
        make_enum(1, 2, False),
        # 4 root values (2 bits)
        make_enum(0, 4, False),
        make_enum(1, 4, False),
        make_enum(2, 4, False),
        make_enum(3, 4, False),
        # 8 root values (3 bits)
        make_enum(0, 8, False),
        make_enum(3, 8, False),
        make_enum(7, 8, False),
        # 16 root values (4 bits)
        make_enum(0, 16, False),
        make_enum(7, 16, False),
        make_enum(15, 16, False),
        # 128 root values (7 bits)
        make_enum(0, 128, False),
        make_enum(63, 128, False),
        make_enum(127, 128, False),
        # 256 root values (8 bits)
        make_enum(0, 256, False),
        make_enum(127, 256, False),
        make_enum(255, 256, False),
        # ---- Extensible cases: value in root ----
        # 4 root + 3 ext, root values
        make_enum(0, 4, True),
        make_enum(1, 4, True),
        make_enum(2, 4, True),
        make_enum(3, 4, True),
        # 2 root + 2 ext, root values
        make_enum(0, 2, True),
        make_enum(1, 2, True),
        # 128 root + 4 ext, root values
        make_enum(0, 128, True),
        make_enum(63, 128, True),
        make_enum(127, 128, True),
        # ---- Extensible cases: value in extension ----
        # 4 root + 3 ext, extension values
        make_enum(4, 4, True),
        make_enum(5, 4, True),
        make_enum(6, 4, True),
        # 2 root + 2 ext, extension values
        make_enum(2, 2, True),
        make_enum(3, 2, True),
        # 1 root + 1 ext, extension value
        make_enum(1, 1, True),
        # 128 root + 4 ext, extension values
        make_enum(128, 128, True),
        make_enum(129, 128, True),
        make_enum(131, 128, True),
    ]

    # Extension count lookup: for extensible cases, map count -> ext_count
    ext_counts = {1: 1, 2: 2, 4: 3, 128: 4}

    for case in cases:
        value = case["value"]
        count = case["count"]
        extensible = case["extensible"]
        ext_count = ext_counts.get(count, 0) if extensible else 0
        for aligned in [True, False]:
            data = encode_enumerated(
                value, count, aligned=aligned, extensible=extensible, ext_count=ext_count
            )
            output = hexlify(data).decode("ascii")
            result = {
                "input": case,
                "aligned": aligned,
                "output": output,
            }
            results.append(result)

    content = json.dumps(results, indent=2)
    with open("enumerated.json", "w") as f:
        f.write(content)

    print(f"Generated {len(results)} enumerated test cases")


if __name__ == "__main__":
    main()
