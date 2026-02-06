#!/usr/bin/env python3

import json
from binascii import hexlify
from pycrate_asn1rt.asnobj_basic import BOOL  # type: ignore


def encode_per(object, aligned=True):
    if aligned:
        return object.to_aper()
    else:
        return object.to_uper()


def encode_boolean(value, aligned=True):
    obj = BOOL(name="BOOLEAN")
    obj.set_val(value)
    return encode_per(obj, aligned)


def main():
    # Create array of test results
    results = []

    # Test cases: all combinations of value and alignment
    test_cases = [
        (True, True),  # value=True, aligned=True
        (True, False),  # value=True, aligned=False
        (False, True),  # value=False, aligned=True
        (False, False),  # value=False, aligned=False
    ]

    for value, aligned in test_cases:
        result = {
            "input": value,
            "aligned": aligned,
            "output": hexlify(encode_boolean(value, aligned)).decode("ascii"),
        }
        results.append(result)

    json_str = json.dumps(results, indent=2)
    print(json_str)  # Keep console output for verification

    # Save to file
    with open("bool.json", "w") as f:
        f.write(json_str)

    pass


if __name__ == "__main__":
    main()
