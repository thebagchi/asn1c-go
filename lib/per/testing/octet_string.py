# Note: unlike BIT STRING, pycrate does NOT have a fragmentation bug for
# OCTET STRING encoding. All pycrate cases are correct.

#
# Erlang/OTP ASN.1 encoder bug (tested on OTP 25 / asn1 5.0.21.1):
# For extensible OCTET STRING types (SIZE (lb..ub, ...)), when the value
# exceeds the constraint upper bound AND the encoded length triggers
# multi-fragment PER encoding (length >= 16384 octets), the Erlang encoder
# drops the leading extension bit, producing output identical to the
# unconstrained encoding path instead of prepending the '1' extension bit.
# This is the same bug as observed for BIT STRING extensible types.
# For example, encoding 131072 octets with SIZE(0..65536, ...):
#   Expected: 80 C4 00 01 ...  (extension bit '1' + fragmented payload)
#   Erlang:      C4 00 01 ...  (missing extension bit, same as unconstrained)
#
# The following 4 extensible cases are excluded due to this bug:
#   make_octet_string(131072, 0, 65536, True)
#   make_octet_string(262144, 0, 131072, True)
#   make_octet_string(524288, 0, 262144, True)
#   make_octet_string(1048576, 0, 524288, True)

import json
import os
import subprocess
import sys
from binascii import hexlify
from pycrate_asn1rt.asnobj_str import OCT_STR
from pycrate_asn1rt.asnobj_construct import ASN1Set, ASN1RangeInt


def encode_per(obj, aligned=True):
    if aligned:
        return obj.to_aper()
    else:
        return obj.to_uper()


def make_octet_string(length, lb=None, ub=None, extensible=False):
    return {"length": length, "lb": lb, "ub": ub, "extensible": extensible}


def gen_octet_string(length):
    pattern = bytes(range(0x00, 0x100))
    full, rem = divmod(length, len(pattern))
    return (pattern * full) + pattern[:rem]


def encode_octet_string(value, aligned=True, lb=None, ub=None, extensible=None):
    obj = OCT_STR(name="OCTET_STRING")
    if lb is not None or ub is not None:
        ev = [] if extensible else None
        if lb is not None and ub is not None:
            constraint = ASN1Set(
                rv=[lb] if lb == ub else [],
                rr=[] if lb == ub else [ASN1RangeInt(lb=lb, ub=ub)],
                ev=ev,
                er=[],
            )
        elif lb is not None:
            constraint = ASN1Set(rv=[], rr=[ASN1RangeInt(lb=lb, ub=None)], ev=ev, er=[])
        elif ub is not None:
            constraint = ASN1Set(rv=[], rr=[ASN1RangeInt(lb=0, ub=ub)], ev=ev, er=[])
        constraint._set_root_bnd()
        obj._const_sz = constraint
    obj.set_val(value)
    return encode_per(obj, aligned)


def main():
    results = []
    cases = [
        make_octet_string(5, None, None, False),
        make_octet_string(5, 0, 10, False),
        make_octet_string(10, 10, None, False),
        make_octet_string(1, None, None, False),
        make_octet_string(1, 0, None, False),
        make_octet_string(1, 0, 2, False),
        make_octet_string(2, None, None, False),
        make_octet_string(2, 0, None, False),
        make_octet_string(2, 0, 4, False),
        make_octet_string(4, None, None, False),
        make_octet_string(4, 0, None, False),
        make_octet_string(4, 0, 8, False),
        make_octet_string(8, None, None, False),
        make_octet_string(8, 0, None, False),
        make_octet_string(8, 0, 16, False),
        make_octet_string(16, None, None, False),
        make_octet_string(16, 0, None, False),
        make_octet_string(16, 0, 32, False),
        make_octet_string(32, None, None, False),
        make_octet_string(32, 0, None, False),
        make_octet_string(32, 0, 64, False),
        make_octet_string(64, None, None, False),
        make_octet_string(64, 0, None, False),
        make_octet_string(64, 0, 128, False),
        make_octet_string(128, None, None, False),
        make_octet_string(128, 0, None, False),
        make_octet_string(128, 0, 256, False),
        make_octet_string(256, None, None, False),
        make_octet_string(256, 0, None, False),
        make_octet_string(256, 0, 512, False),
        make_octet_string(512, None, None, False),
        make_octet_string(512, 0, None, False),
        make_octet_string(512, 0, 1024, False),
        make_octet_string(1024, None, None, False),
        make_octet_string(1024, 0, None, False),
        make_octet_string(1024, 0, 2048, False),
        make_octet_string(2048, None, None, False),
        make_octet_string(2048, 0, None, False),
        make_octet_string(2048, 0, 4096, False),
        make_octet_string(4096, None, None, False),
        make_octet_string(4096, 0, None, False),
        make_octet_string(4096, 0, 8192, False),
        make_octet_string(8192, None, None, False),
        make_octet_string(8192, 0, None, False),
        make_octet_string(8192, 0, 16384, False),
        make_octet_string(16384, None, None, False),
        make_octet_string(16384, 0, None, False),
        make_octet_string(16384, 0, 32768, False),
        make_octet_string(32768, None, None, False),
        make_octet_string(32768, 0, None, False),
        make_octet_string(32768, 0, 65536, False),
        make_octet_string(65536, None, None, False),
        make_octet_string(65536, 0, None, False),
        make_octet_string(65536, 0, 131072, False),
        make_octet_string(131072, None, None, False),
        make_octet_string(131072, 0, None, False),
        make_octet_string(131072, 0, 262144, False),
        make_octet_string(262144, None, None, False),
        make_octet_string(262144, 0, None, False),
        make_octet_string(262144, 0, 524288, False),
        make_octet_string(524288, None, None, False),
        make_octet_string(524288, 0, None, False),
        make_octet_string(524288, 0, 1048576, False),
        make_octet_string(1048576, None, None, False),
        make_octet_string(1048576, 0, None, False),
        make_octet_string(1048576, 0, 2097152, False),
        make_octet_string(1, 0, 0, True),
        make_octet_string(2, 0, 1, True),
        make_octet_string(4, 0, 2, True),
        make_octet_string(8, 0, 4, True),
        make_octet_string(16, 0, 8, True),
        make_octet_string(32, 0, 16, True),
        make_octet_string(64, 0, 32, True),
        make_octet_string(128, 0, 64, True),
        make_octet_string(256, 0, 128, True),
        make_octet_string(512, 0, 256, True),
        make_octet_string(1024, 0, 512, True),
        make_octet_string(2048, 0, 1024, True),
        make_octet_string(4096, 0, 2048, True),
        make_octet_string(8192, 0, 4096, True),
        make_octet_string(16384, 0, 8192, True),
        make_octet_string(32768, 0, 16384, True),
        make_octet_string(65536, 0, 32768, True),
        make_octet_string(131072, 0, 65536, True),
        make_octet_string(262144, 0, 131072, True),
        make_octet_string(524288, 0, 262144, True),
        make_octet_string(1048576, 0, 524288, True),
    ]
    for case in cases:
        length = case["length"]
        lb = case["lb"]
        ub = case["ub"]
        extensible = case["extensible"]
        value = gen_octet_string(length)
        for aligned in [True, False]:
            data = encode_octet_string(value, aligned, lb, ub, extensible)
            output = hexlify(data).decode("ascii")
            result = {
                "input": case,
                "output": output,
                "aligned": aligned,
            }
            results.append(result)
    # All cases encoded via Erlang/OTP (encode_octetstring.erl) for
    # fragmentation-correct results. May duplicate pycrate entries for small
    # sizes, but provides a complete Erlang-verified reference set.
    erlang_cases = [
        make_octet_string(5, None, None, False),
        make_octet_string(5, 0, 10, False),
        make_octet_string(10, 10, None, False),
        make_octet_string(1, None, None, False),
        make_octet_string(1, 0, None, False),
        make_octet_string(1, 0, 2, False),
        make_octet_string(2, None, None, False),
        make_octet_string(2, 0, None, False),
        make_octet_string(2, 0, 4, False),
        make_octet_string(4, None, None, False),
        make_octet_string(4, 0, None, False),
        make_octet_string(4, 0, 8, False),
        make_octet_string(8, None, None, False),
        make_octet_string(8, 0, None, False),
        make_octet_string(8, 0, 16, False),
        make_octet_string(16, None, None, False),
        make_octet_string(16, 0, None, False),
        make_octet_string(16, 0, 32, False),
        make_octet_string(32, None, None, False),
        make_octet_string(32, 0, None, False),
        make_octet_string(32, 0, 64, False),
        make_octet_string(64, None, None, False),
        make_octet_string(64, 0, None, False),
        make_octet_string(64, 0, 128, False),
        make_octet_string(128, None, None, False),
        make_octet_string(128, 0, None, False),
        make_octet_string(128, 0, 256, False),
        make_octet_string(256, None, None, False),
        make_octet_string(256, 0, None, False),
        make_octet_string(256, 0, 512, False),
        make_octet_string(512, None, None, False),
        make_octet_string(512, 0, None, False),
        make_octet_string(512, 0, 1024, False),
        make_octet_string(1024, None, None, False),
        make_octet_string(1024, 0, None, False),
        make_octet_string(1024, 0, 2048, False),
        make_octet_string(2048, None, None, False),
        make_octet_string(2048, 0, None, False),
        make_octet_string(2048, 0, 4096, False),
        make_octet_string(4096, None, None, False),
        make_octet_string(4096, 0, None, False),
        make_octet_string(4096, 0, 8192, False),
        make_octet_string(8192, None, None, False),
        make_octet_string(8192, 0, None, False),
        make_octet_string(8192, 0, 16384, False),
        make_octet_string(16384, None, None, False),
        make_octet_string(16384, 0, None, False),
        make_octet_string(16384, 0, 32768, False),
        make_octet_string(32768, None, None, False),
        make_octet_string(32768, 0, None, False),
        make_octet_string(32768, 0, 65536, False),
        make_octet_string(65536, None, None, False),
        make_octet_string(65536, 0, None, False),
        make_octet_string(65536, 0, 131072, False),
        make_octet_string(131072, None, None, False),
        make_octet_string(131072, 0, None, False),
        make_octet_string(131072, 0, 262144, False),
        make_octet_string(262144, None, None, False),
        make_octet_string(262144, 0, None, False),
        make_octet_string(262144, 0, 524288, False),
        make_octet_string(524288, None, None, False),
        make_octet_string(524288, 0, None, False),
        make_octet_string(524288, 0, 1048576, False),
        make_octet_string(1048576, None, None, False),
        make_octet_string(1048576, 0, None, False),
        make_octet_string(1048576, 0, 2097152, False),
        make_octet_string(1, 0, 0, True),
        make_octet_string(2, 0, 1, True),
        make_octet_string(4, 0, 2, True),
        make_octet_string(8, 0, 4, True),
        make_octet_string(16, 0, 8, True),
        make_octet_string(32, 0, 16, True),
        make_octet_string(64, 0, 32, True),
        make_octet_string(128, 0, 64, True),
        make_octet_string(256, 0, 128, True),
        make_octet_string(512, 0, 256, True),
        make_octet_string(1024, 0, 512, True),
        make_octet_string(2048, 0, 1024, True),
        make_octet_string(4096, 0, 2048, True),
        make_octet_string(8192, 0, 4096, True),
        make_octet_string(16384, 0, 8192, True),
        make_octet_string(32768, 0, 16384, True),
        make_octet_string(65536, 0, 32768, True),
        # Extensible cases with length >= 16384 octets beyond ub excluded
        # due to Erlang/OTP extension bit bug (see comment above).
    ]
    for case in erlang_cases:
        length = case["length"]
        lb = case["lb"]
        ub = case["ub"]
        extensible = case["extensible"]
        type_name = asn1_type_name(lb, ub, extensible)
        for aligned in [True, False]:
            output = encode_octetstring_erl(type_name, length, aligned)
            results.append(
                {
                    "input": case,
                    "output": output,
                    "aligned": aligned,
                }
            )

    with open("octet_string.json", "w") as f:
        json.dump(results, f, indent=2)


# ---------------------------------------------------------------------------
# Erlang-based encoder (calls encode_octetstring.erl for fragmentation-correct
# results on large octet strings).
# ---------------------------------------------------------------------------

_ERLANG_DIR_ = os.path.join(os.path.dirname(os.path.abspath(__file__)), "erlang")


def asn1_type_name(lb, ub, extensible):
    lb_s = "NULL" if lb is None else str(lb)
    ub_s = "NULL" if ub is None else str(ub)
    ext_s = "TRUE" if extensible else "FALSE"
    return f"OCTETSTRING-{lb_s}-{ub_s}-{ext_s}"


def encode_octetstring_erl(type_name, length, aligned):
    script = os.path.join(_ERLANG_DIR_, "encode_octetstring.erl")
    cmd = ["escript", script, "-name", type_name, "-length", str(length)]
    if aligned:
        cmd.append("-aligned")
    result = subprocess.run(cmd, cwd=_ERLANG_DIR_, capture_output=True, text=True)
    if result.returncode != 0:
        print(
            f"Erlang encode error for {type_name} length={length} aligned={aligned}:",
            file=sys.stderr,
        )
        print(result.stderr, file=sys.stderr)
        sys.exit(1)
    return result.stdout.strip().lower()


if __name__ == "__main__":
    main()
