#!/usr/bin/env python3

import json
from binascii import hexlify
from pycrate_asn1rt.asnobj_basic import BOOL  # type: ignore


def encode_per(obj, aligned=True):
    if aligned:
        return obj.to_aper()
    else:
        return obj.to_uper()


def encode_boolean(value, aligned=True):
    obj = BOOL(name="BOOLEAN")
    obj.set_val(value)
    return encode_per(obj, aligned)


def main():
    results = []
    cases = [
        {"value": True, "aligned": True},
        {"value": True, "aligned": False},
        {"value": False, "aligned": True},
        {"value": False, "aligned": False},
    ]
    for case in cases:
        value = case["value"]
        aligned = case["aligned"]
        data = encode_boolean(value, aligned)
        output = hexlify(data).decode("ascii")
        result = {
            "input": value,
            "aligned": aligned,
            "output": output,
        }
        results.append(result)

    content = json.dumps(results, indent=2)
    with open("bool.json", "w") as f:
        f.write(content)
    pass


if __name__ == "__main__":
    main()
