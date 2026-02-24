# pycrate bug: BIT_STRING PER fragmentation (APER & UPER) is broken for
# bit lengths >= 16384 when using unconstrained/semi-constrained/extensible
# encoding paths.
# Root cause: operator precedence bug in encode_fragbytes() in codecs.py
# where buf[off:off+fs>>3] evaluates as buf[off:(off+fs)>>3] instead of
# buf[off:off+(fs>>3)].
# This silently corrupts data for 2 fragments (>= 65536 bits) and crashes
# with IndexError for 3+ fragments (>= 147456 bits).
# Constrained cases with ub < 65536 are unaffected (they bypass fragmentation).

import json
from binascii import hexlify
from pycrate_asn1rt.asnobj_str import BIT_STR
from pycrate_asn1rt.asnobj_construct import ASN1Set, ASN1RangeInt


def encode_per(obj, aligned=True):
    if aligned:
        return obj.to_aper()
    else:
        return obj.to_uper()


def make_bit_string(length, lb=None, ub=None, extensible=False):
    return {"length": length, "lb": lb, "ub": ub, "extensible": extensible}


def gen_bit_string(length):
    # Generate alternating bits: 0, 1, 0, 1, ...
    val = 0
    for i in range(length):
        val = (val << 1) | (i % 2)
    return (val, length)


def encode_bit_string(value, aligned=True, lb=None, ub=None, extensible=None):
    obj = BIT_STR(name="BIT_STRING")
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
        make_bit_string(5, None, None, False),
        make_bit_string(5, 0, 10, False),
        make_bit_string(10, 10, None, False),
        make_bit_string(1, None, None, False),
        make_bit_string(1, 0, None, False),
        make_bit_string(1, 0, 2, False),
        make_bit_string(2, None, None, False),
        make_bit_string(2, 0, None, False),
        make_bit_string(2, 0, 4, False),
        make_bit_string(4, None, None, False),
        make_bit_string(4, 0, None, False),
        make_bit_string(4, 0, 8, False),
        make_bit_string(8, None, None, False),
        make_bit_string(8, 0, None, False),
        make_bit_string(8, 0, 16, False),
        make_bit_string(16, None, None, False),
        make_bit_string(16, 0, None, False),
        make_bit_string(16, 0, 32, False),
        make_bit_string(32, None, None, False),
        make_bit_string(32, 0, None, False),
        make_bit_string(32, 0, 64, False),
        make_bit_string(64, None, None, False),
        make_bit_string(64, 0, None, False),
        make_bit_string(64, 0, 128, False),
        make_bit_string(128, None, None, False),
        make_bit_string(128, 0, None, False),
        make_bit_string(128, 0, 256, False),
        make_bit_string(256, None, None, False),
        make_bit_string(256, 0, None, False),
        make_bit_string(256, 0, 512, False),
        make_bit_string(512, None, None, False),
        make_bit_string(512, 0, None, False),
        make_bit_string(512, 0, 1024, False),
        make_bit_string(1024, None, None, False),
        make_bit_string(1024, 0, None, False),
        make_bit_string(1024, 0, 2048, False),
        make_bit_string(2048, None, None, False),
        make_bit_string(2048, 0, None, False),
        make_bit_string(2048, 0, 4096, False),
        make_bit_string(4096, None, None, False),
        make_bit_string(4096, 0, None, False),
        make_bit_string(4096, 0, 8192, False),
        make_bit_string(8192, None, None, False),
        make_bit_string(8192, 0, None, False),
        make_bit_string(8192, 0, 16384, False),
        make_bit_string(16384, None, None, False),
        make_bit_string(16384, 0, None, False),
        make_bit_string(16384, 0, 32768, False),
        make_bit_string(32768, None, None, False),
        make_bit_string(32768, 0, None, False),
        make_bit_string(32768, 0, 65536, False),
        make_bit_string(65536, None, None, False),
        make_bit_string(65536, 0, None, False),
        make_bit_string(65536, 0, 131072, False),
        make_bit_string(1, 0, 0, True),
        make_bit_string(2, 0, 1, True),
        make_bit_string(4, 0, 2, True),
        make_bit_string(8, 0, 4, True),
        make_bit_string(16, 0, 8, True),
        make_bit_string(32, 0, 16, True),
        make_bit_string(64, 0, 32, True),
        make_bit_string(128, 0, 64, True),
        make_bit_string(256, 0, 128, True),
        make_bit_string(512, 0, 256, True),
        make_bit_string(1024, 0, 512, True),
        make_bit_string(2048, 0, 1024, True),
        make_bit_string(4096, 0, 2048, True),
        make_bit_string(8192, 0, 4096, True),
        make_bit_string(16384, 0, 8192, True),
        make_bit_string(32768, 0, 16384, True),
        make_bit_string(65536, 0, 32768, True),
    ]
    for case in cases:
        length = case["length"]
        lb = case["lb"]
        ub = case["ub"]
        extensible = case["extensible"]
        value = gen_bit_string(length)
        for aligned in [True, False]:
            data = encode_bit_string(value, aligned, lb, ub, extensible)
            output = hexlify(data).decode("ascii")
            result = {
                "input": case,
                "output": output,
                "aligned": aligned,
            }
            results.append(result)
    with open("bit_string.json", "w") as f:
        json.dump(results, f, indent=2)


if __name__ == "__main__":
    main()
