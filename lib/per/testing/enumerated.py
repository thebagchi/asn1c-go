#!/usr/bin/env python3

import json
import os
import subprocess
import sys
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
        # ---- Large extension indices (NSNNWN boundary) ----
        # Extension index 62 (last value in 6-bit NSNNWN - 1)
        make_enum(4 + 62, 4, True),
        # Extension index 63 (last value in 6-bit NSNNWN)
        make_enum(4 + 63, 4, True),
        # Extension index 64 (first value that triggers semi-constrained NSNNWN)
        make_enum(4 + 64, 4, True),
        # Extension index 65
        make_enum(4 + 65, 4, True),
        # Extension index 127
        make_enum(4 + 127, 4, True),
        # Extension index 128
        make_enum(4 + 128, 4, True),
        # Extension index 255
        make_enum(4 + 255, 4, True),
        # ---- Non-power-of-2 counts (tests bit width calculation) ----
        # 3 root values (needs 2 bits, same as count=4)
        make_enum(0, 3, False),
        make_enum(1, 3, False),
        make_enum(2, 3, False),
        # 5 root values (needs 3 bits)
        make_enum(0, 5, False),
        make_enum(4, 5, False),
        # 6 root values (needs 3 bits)
        make_enum(0, 6, False),
        make_enum(5, 6, False),
        # 7 root values (needs 3 bits)
        make_enum(0, 7, False),
        make_enum(6, 7, False),
        # 9 root values (needs 4 bits)
        make_enum(0, 9, False),
        make_enum(8, 9, False),
        # 10 root values (needs 4 bits)
        make_enum(0, 10, False),
        make_enum(9, 10, False),
        # 15 root values (needs 4 bits)
        make_enum(0, 15, False),
        make_enum(14, 15, False),
        # 17 root values (needs 5 bits)
        make_enum(0, 17, False),
        make_enum(16, 17, False),
        # 33 root values (needs 6 bits)
        make_enum(0, 33, False),
        make_enum(32, 33, False),
        # 65 root values (needs 7 bits)
        make_enum(0, 65, False),
        make_enum(64, 65, False),
        # 129 root values (needs 8 bits)
        make_enum(0, 129, False),
        make_enum(128, 129, False),
        # 255 root values (needs 8 bits)
        make_enum(0, 255, False),
        make_enum(254, 255, False),
        # ---- Non-power-of-2 extensible counts ----
        # 3 root + 2 ext, root and extension
        make_enum(0, 3, True),
        make_enum(2, 3, True),
        make_enum(3, 3, True),
        make_enum(4, 3, True),
        # 7 root + 2 ext, root and extension
        make_enum(0, 7, True),
        make_enum(6, 7, True),
        make_enum(7, 7, True),
        make_enum(8, 7, True),
        # 17 root + 2 ext
        make_enum(0, 17, True),
        make_enum(16, 17, True),
        make_enum(17, 17, True),
        make_enum(18, 17, True),
        # 129 root + 2 ext
        make_enum(0, 129, True),
        make_enum(128, 129, True),
        make_enum(129, 129, True),
        make_enum(130, 129, True),
        # ---- Extensible count=1, root value ----
        make_enum(0, 1, True),
    ]

    # Extension count lookup: for extensible cases, map count -> ext_count
    ext_counts = {1: 1, 2: 2, 3: 2, 4: 256, 7: 2, 17: 2, 128: 4, 129: 2}

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

    # --- Erlang cross-validation ---
    # Erlang member naming: m-1 is value 0, m-2 is value 1, etc.
    # ASN.1 type naming: ENUM-{root_count}-{ext_count}-{TRUE|FALSE}
    erlang_cases = [
        # Non-extensible: power-of-2 counts
        make_enum(0, 2, False),
        make_enum(1, 2, False),
        make_enum(0, 4, False),
        make_enum(3, 4, False),
        make_enum(0, 8, False),
        make_enum(7, 8, False),
        make_enum(0, 16, False),
        make_enum(15, 16, False),
        make_enum(0, 128, False),
        make_enum(127, 128, False),
        make_enum(0, 256, False),
        make_enum(255, 256, False),
        # Non-extensible: non-power-of-2 counts
        make_enum(0, 3, False),
        make_enum(2, 3, False),
        make_enum(0, 5, False),
        make_enum(4, 5, False),
        make_enum(0, 6, False),
        make_enum(5, 6, False),
        make_enum(0, 7, False),
        make_enum(6, 7, False),
        make_enum(0, 9, False),
        make_enum(8, 9, False),
        make_enum(0, 10, False),
        make_enum(9, 10, False),
        make_enum(0, 15, False),
        make_enum(14, 15, False),
        make_enum(0, 17, False),
        make_enum(16, 17, False),
        make_enum(0, 33, False),
        make_enum(32, 33, False),
        make_enum(0, 65, False),
        make_enum(64, 65, False),
        make_enum(0, 129, False),
        make_enum(128, 129, False),
        make_enum(0, 255, False),
        make_enum(254, 255, False),
        # Extensible: root values
        make_enum(0, 1, True),
        make_enum(0, 2, True),
        make_enum(1, 2, True),
        make_enum(0, 3, True),
        make_enum(2, 3, True),
        make_enum(0, 4, True),
        make_enum(3, 4, True),
        make_enum(0, 7, True),
        make_enum(6, 7, True),
        make_enum(0, 17, True),
        make_enum(16, 17, True),
        make_enum(0, 128, True),
        make_enum(127, 128, True),
        make_enum(0, 129, True),
        make_enum(128, 129, True),
        # Extensible: extension values
        make_enum(1, 1, True),
        make_enum(2, 2, True),
        make_enum(3, 2, True),
        make_enum(3, 3, True),
        make_enum(4, 3, True),
        make_enum(4, 4, True),
        make_enum(5, 4, True),
        make_enum(7, 7, True),
        make_enum(8, 7, True),
        make_enum(17, 17, True),
        make_enum(18, 17, True),
        make_enum(128, 128, True),
        make_enum(131, 128, True),
        make_enum(129, 129, True),
        make_enum(130, 129, True),
    ]
    for case in erlang_cases:
        value = case["value"]
        count = case["count"]
        extensible = case["extensible"]
        ext_count = ext_counts.get(count, 0) if extensible else 0
        type_name = asn1_type_name(count, ext_count, extensible)
        member_name = f"m-{value + 1}"
        for aligned in [True, False]:
            output = encode_enumerated_erl(type_name, member_name, aligned)
            results.append(
                {
                    "input": case,
                    "aligned": aligned,
                    "output": output,
                }
            )

    content = json.dumps(results, indent=2)
    with open("enumerated.json", "w") as f:
        f.write(content)

    print(f"Generated {len(results)} enumerated test cases")


# ---------------------------------------------------------------------------
# Erlang-based encoder (calls encode_enumerated.erl for cross-validation).
# ---------------------------------------------------------------------------

_ERLANG_DIR_ = os.path.join(os.path.dirname(os.path.abspath(__file__)), "erlang")


def asn1_type_name(count, ext_count, extensible):
    ext_s = "TRUE" if extensible else "FALSE"
    return f"ENUM-{count}-{ext_count}-{ext_s}"


def encode_enumerated_erl(type_name, member_name, aligned):
    script = os.path.join(_ERLANG_DIR_, "encode_enumerated.erl")
    cmd = ["escript", script, "-name", type_name, "-value", member_name]
    if aligned:
        cmd.append("-aligned")
    result = subprocess.run(cmd, cwd=_ERLANG_DIR_, capture_output=True, text=True)
    if result.returncode != 0:
        print(
            f"Erlang encode error for {type_name} value={member_name} aligned={aligned}:",
            file=sys.stderr,
        )
        print(result.stderr, file=sys.stderr)
        sys.exit(1)
    return result.stdout.strip().lower()


if __name__ == "__main__":
    main()
