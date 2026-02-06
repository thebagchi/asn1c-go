#!/usr/bin/env python3

import json
from binascii import hexlify
from pycrate_asn1rt.asnobj_basic import INT  # type: ignore
from pycrate_asn1rt.asnobj_construct import ASN1Set, ASN1RangeInt  # type: ignore


def encode_per(obj, aligned=True):
    if aligned:
        return obj.to_aper()
    else:
        return obj.to_uper()


def encode_integer(value, aligned=True, lb=None, ub=None, extensible=None):
    obj = INT(name="INTEGER")
    if lb is not None or ub is not None:
        if lb is not None and ub is not None:
            constraint = ASN1Set(
                rv=[lb] if lb == ub else [],
                rr=[] if lb == ub else [ASN1RangeInt(lb=lb, ub=ub)],
                ev=None,
                er=[],
            )
        elif lb is not None:
            constraint = ASN1Set(
                rv=[], rr=[ASN1RangeInt(lb=lb, ub=None)], ev=None, er=[]
            )
        elif ub is not None:
            constraint = ASN1Set(rv=[], rr=[ASN1RangeInt(lb=0, ub=ub)], ev=None, er=[])

        if extensible:
            constraint.ext = True
        constraint._init(True, True)
        constraint._set_root_bnd()
        obj._const_val = constraint
    obj.set_val(value)
    return encode_per(obj, aligned)


def main():
    results = []
    cases = [
        {"value": 10, "lb": 0, "ub": 100, "extensible": False},
        {"value": 10, "lb": 0, "ub": 200, "extensible": False},
        {"value": 10, "lb": None, "ub": None, "extensible": False},
        {"value": 0, "lb": 0, "ub": 100, "extensible": False},
        {"value": 0, "lb": 0, "ub": 200, "extensible": False},
        {"value": 100, "lb": 0, "ub": 100, "extensible": False},
        {"value": 200, "lb": 0, "ub": 200, "extensible": False},
    ]
    for case in cases:
        value = case["value"]
        lb = case["lb"]
        ub = case["ub"]
        extensible = case["extensible"]
        for aligned in [True, False]:
            data = encode_integer(value, aligned, lb, ub, extensible)
            output = hexlify(data).decode("ascii")
            result = {
                "input": {"value": value, "lb": lb, "ub": ub, "extensible": extensible},
                "output": output,
                "aligned": aligned,
            }
            results.append(result)
    with open("integer.json", "w") as f:
        json.dump(results, f, indent=2)
    pass


if __name__ == "__main__":
    main()
