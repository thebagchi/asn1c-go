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
        {"value": 0, "lb": None, "ub": None, "extensible": False},
        {"value": 1, "lb": None, "ub": None, "extensible": False},
        {"value": 127, "lb": None, "ub": None, "extensible": False},
        {"value": 128, "lb": None, "ub": None, "extensible": False},
        {"value": 255, "lb": None, "ub": None, "extensible": False},
        {"value": 256, "lb": None, "ub": None, "extensible": False},
        {"value": 32767, "lb": None, "ub": None, "extensible": False},
        {"value": 32768, "lb": None, "ub": None, "extensible": False},
        {"value": 65535, "lb": None, "ub": None, "extensible": False},
        {"value": 65536, "lb": None, "ub": None, "extensible": False},
        {"value": 131072, "lb": None, "ub": None, "extensible": False},
        {"value": 262144, "lb": None, "ub": None, "extensible": False},
        {"value": 524288, "lb": None, "ub": None, "extensible": False},
        {"value": 1048576, "lb": None, "ub": None, "extensible": False},
        {"value": 2097152, "lb": None, "ub": None, "extensible": False},
        {"value": 4194304, "lb": None, "ub": None, "extensible": False},
        {"value": 8388607, "lb": None, "ub": None, "extensible": False},
        {"value": 8388608, "lb": None, "ub": None, "extensible": False},
        {"value": 16777216, "lb": None, "ub": None, "extensible": False},
        {"value": 33554432, "lb": None, "ub": None, "extensible": False},
        {"value": 67108864, "lb": None, "ub": None, "extensible": False},
        {"value": 134217728, "lb": None, "ub": None, "extensible": False},
        {"value": 268435456, "lb": None, "ub": None, "extensible": False},
        {"value": -1, "lb": None, "ub": None, "extensible": False},
        {"value": -128, "lb": None, "ub": None, "extensible": False},
        {"value": -129, "lb": None, "ub": None, "extensible": False},
        {"value": -32768, "lb": None, "ub": None, "extensible": False},
        {"value": -32769, "lb": None, "ub": None, "extensible": False},
        {"value": 0, "lb": 0, "ub": 100, "extensible": False},
        {"value": 0, "lb": 0, "ub": 200, "extensible": False},
        {"value": 100, "lb": 0, "ub": 100, "extensible": False},
        {"value": 200, "lb": 0, "ub": 200, "extensible": False},
        {"value": 50, "lb": 10, "ub": None, "extensible": False},
        {"value": 10, "lb": 10, "ub": None, "extensible": False},
        {"value": 100, "lb": 10, "ub": None, "extensible": False},
        {"value": 0, "lb": 0, "ub": None, "extensible": False},
        {"value": 255, "lb": 0, "ub": None, "extensible": False},
        {"value": 256, "lb": 0, "ub": None, "extensible": False},
        {"value": -5, "lb": -10, "ub": None, "extensible": False},
        {"value": 0, "lb": -10, "ub": None, "extensible": False},
        {"value": 10, "lb": -10, "ub": None, "extensible": False},
        {"value": 1000, "lb": 100, "ub": None, "extensible": False},
        {"value": 65535, "lb": 0, "ub": None, "extensible": False},
        {"value": 65536, "lb": 0, "ub": None, "extensible": False},
        {"value": 131072, "lb": 0, "ub": None, "extensible": False},
        {"value": 262144, "lb": 0, "ub": None, "extensible": False},
        {"value": 524288, "lb": 0, "ub": None, "extensible": False},
        {"value": 1048576, "lb": 0, "ub": None, "extensible": False},
        {"value": 2097152, "lb": 0, "ub": None, "extensible": False},
        {"value": 4194304, "lb": 0, "ub": None, "extensible": False},
        {"value": 8388608, "lb": 0, "ub": None, "extensible": False},
        {"value": 16777216, "lb": 0, "ub": None, "extensible": False},
        {"value": 33554432, "lb": 0, "ub": None, "extensible": False},
        {"value": 67108864, "lb": 0, "ub": None, "extensible": False},
        {"value": 134217728, "lb": 0, "ub": None, "extensible": False},
        {"value": 268435456, "lb": 0, "ub": None, "extensible": False},
        {"value": 0, "lb": 0, "ub": 1, "extensible": False},
        {"value": 1, "lb": 0, "ub": 1, "extensible": False},
        {"value": 0, "lb": 0, "ub": 2, "extensible": False},
        {"value": 2, "lb": 0, "ub": 2, "extensible": False},
        {"value": 0, "lb": 0, "ub": 4, "extensible": False},
        {"value": 4, "lb": 0, "ub": 4, "extensible": False},
        {"value": 0, "lb": 0, "ub": 8, "extensible": False},
        {"value": 8, "lb": 0, "ub": 8, "extensible": False},
        {"value": 0, "lb": 0, "ub": 16, "extensible": False},
        {"value": 16, "lb": 0, "ub": 16, "extensible": False},
        {"value": 0, "lb": 0, "ub": 32, "extensible": False},
        {"value": 32, "lb": 0, "ub": 32, "extensible": False},
        {"value": 0, "lb": 0, "ub": 64, "extensible": False},
        {"value": 64, "lb": 0, "ub": 64, "extensible": False},
        {"value": 0, "lb": 0, "ub": 128, "extensible": False},
        {"value": 128, "lb": 0, "ub": 128, "extensible": False},
        {"value": 0, "lb": 0, "ub": 256, "extensible": False},
        {"value": 256, "lb": 0, "ub": 256, "extensible": False},
        {"value": 0, "lb": 0, "ub": 512, "extensible": False},
        {"value": 512, "lb": 0, "ub": 512, "extensible": False},
        {"value": 0, "lb": 0, "ub": 1024, "extensible": False},
        {"value": 1024, "lb": 0, "ub": 1024, "extensible": False},
        {"value": 0, "lb": 0, "ub": 2048, "extensible": False},
        {"value": 2048, "lb": 0, "ub": 2048, "extensible": False},
        {"value": 0, "lb": 0, "ub": 4096, "extensible": False},
        {"value": 4096, "lb": 0, "ub": 4096, "extensible": False},
        {"value": 0, "lb": 0, "ub": 8192, "extensible": False},
        {"value": 8192, "lb": 0, "ub": 8192, "extensible": False},
        {"value": 0, "lb": 0, "ub": 16384, "extensible": False},
        {"value": 16384, "lb": 0, "ub": 16384, "extensible": False},
        {"value": 0, "lb": 0, "ub": 32768, "extensible": False},
        {"value": 32768, "lb": 0, "ub": 32768, "extensible": False},
        {"value": 0, "lb": 0, "ub": 65536, "extensible": False},
        {"value": 65536, "lb": 0, "ub": 65536, "extensible": False},
        {"value": 0, "lb": 0, "ub": 131072, "extensible": False},
        {"value": 131072, "lb": 0, "ub": 131072, "extensible": False},
        {"value": 0, "lb": 0, "ub": 262144, "extensible": False},
        {"value": 262144, "lb": 0, "ub": 262144, "extensible": False},
        {"value": 0, "lb": 0, "ub": 524288, "extensible": False},
        {"value": 524288, "lb": 0, "ub": 524288, "extensible": False},
        {"value": 0, "lb": 0, "ub": 1048576, "extensible": False},
        {"value": 1048576, "lb": 0, "ub": 1048576, "extensible": False},
        {"value": 0, "lb": 0, "ub": 2097152, "extensible": False},
        {"value": 2097152, "lb": 0, "ub": 2097152, "extensible": False},
        {"value": 0, "lb": 0, "ub": 4194304, "extensible": False},
        {"value": 4194304, "lb": 0, "ub": 4194304, "extensible": False},
        {"value": 0, "lb": 0, "ub": 8388608, "extensible": False},
        {"value": 8388608, "lb": 0, "ub": 8388608, "extensible": False},
        {"value": 0, "lb": 0, "ub": 16777216, "extensible": False},
        {"value": 16777216, "lb": 0, "ub": 16777216, "extensible": False},
        {"value": 0, "lb": 0, "ub": 33554432, "extensible": False},
        {"value": 33554432, "lb": 0, "ub": 33554432, "extensible": False},
        {"value": 0, "lb": 0, "ub": 67108864, "extensible": False},
        {"value": 67108864, "lb": 0, "ub": 67108864, "extensible": False},
        {"value": 0, "lb": 0, "ub": 134217728, "extensible": False},
        {"value": 134217728, "lb": 0, "ub": 134217728, "extensible": False},
        {"value": 0, "lb": 0, "ub": 268435456, "extensible": False},
        {"value": 268435456, "lb": 0, "ub": 268435456, "extensible": False},
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
