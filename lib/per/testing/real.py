#!/usr/bin/env python3

import json
import os
import struct
import subprocess
import sys
from binascii import hexlify

from pycrate_asn1rt.asnobj_basic import REAL  # type: ignore


def encode_per(obj, aligned=True):
    if aligned:
        return obj.to_aper()
    else:
        return obj.to_uper()


def float_to_real_tuple(value):
    """Convert a Python float to pycrate REAL (mantissa, base, exponent) tuple.

    This extracts the IEEE 754 components and normalizes the mantissa to be odd
    (matching the CER/DER canonical encoding per X.690 11.3.1).
    """
    if value == 0.0:
        return (0, 10, 0)  # pycrate expects base 10 for zero

    # Use struct to extract IEEE 754 bits
    bits = struct.unpack(">Q", struct.pack(">d", value))[0]
    sign = (bits >> 63) & 1
    bexp = (bits >> 52) & 0x7FF
    frac = bits & 0xFFFFFFFFFFFFF  # 52-bit mantissa

    if bexp == 0:
        # Subnormal
        mantissa = frac
        exponent = -1022 - 52
    else:
        # Normal
        mantissa = (1 << 52) | frac
        exponent = bexp - 1023 - 52

    if sign == 1:
        mantissa = -mantissa

    # Normalize: make mantissa odd
    while mantissa != 0 and mantissa % 2 == 0:
        mantissa //= 2
        exponent += 1

    return (mantissa, 2, exponent)


def encode_real(value, aligned=True):
    """Encode a float64 value as PER REAL. Returns the encoded bytes."""
    obj = REAL(name="REAL")
    real_val = float_to_real_tuple(value)
    obj.set_val(real_val)
    return encode_per(obj, aligned)


def make_real(value):
    """Build an input dict for a REAL test case."""
    return {"value": value}


def main():
    results = []

    cases = [
        # Zero
        make_real(0.0),
        # Simple positive integers (exact in float64)
        make_real(1.0),
        make_real(2.0),
        make_real(3.0),
        make_real(-1.0),
        make_real(-2.0),
        make_real(-3.0),
        # Powers of 2
        make_real(0.5),
        make_real(0.25),
        make_real(0.125),
        make_real(4.0),
        make_real(8.0),
        make_real(16.0),
        make_real(256.0),
        make_real(1024.0),
        make_real(65536.0),
        # Simple fractions
        make_real(1.5),
        make_real(2.5),
        make_real(3.75),
        make_real(-0.5),
        make_real(-1.5),
        make_real(-3.75),
        # Common values
        make_real(10.0),
        make_real(100.0),
        make_real(1000.0),
        make_real(-10.0),
        make_real(-100.0),
        # Small values
        make_real(1e-10),
        make_real(1e-20),
        make_real(-1e-10),
        # Large values
        make_real(1e10),
        make_real(1e20),
        make_real(1e50),
        make_real(-1e10),
        make_real(-1e20),
        # Values requiring multi-byte exponents
        make_real(1e100),
        make_real(1e200),
        make_real(1e-100),
        make_real(1e-200),
        make_real(-1e100),
        # Pi and e approximations
        make_real(3.141592653589793),
        make_real(2.718281828459045),
        make_real(-3.141592653589793),
        # Max/min normal float64 values
        make_real(1.7976931348623157e308),
        make_real(-1.7976931348623157e308),
        make_real(2.2250738585072014e-308),
        # Smallest subnormal
        make_real(5e-324),
        # Negative edge cases
        make_real(-5e-324),
        make_real(-2.2250738585072014e-308),
    ]

    for case in cases:
        value = case["value"]
        for aligned in [True, False]:
            data = encode_real(value, aligned)
            output = hexlify(data).decode("ascii")
            result = {
                "input": case,
                "aligned": aligned,
                "output": output,
            }
            results.append(result)

    # Special values: PLUS-INFINITY, MINUS-INFINITY, NOT-A-NUMBER, minus-zero
    # These are encoded per X.690 8.5.9:
    #   PLUS-INFINITY:  length=1, content=0x40
    #   MINUS-INFINITY: length=1, content=0x41
    #   NOT-A-NUMBER:   length=1, content=0x42
    #   Minus zero:     length=1, content=0x43
    # PER wraps this via unconstrained length determinant (EncodeOctetString with no constraints)
    # pycrate does not support these directly, so we hardcode the encodings.
    special_cases = [
        ("Inf", "0140"),
        ("-Inf", "0141"),
        ("NaN", "0142"),
        ("-0", "0143"),
    ]
    for label, output in special_cases:
        for aligned in [True, False]:
            result = {
                "input": {"value": label},
                "aligned": aligned,
                "output": output,
            }
            results.append(result)

    # --- Erlang cross-validation ---
    # Only non-special, non-zero floats (Erlang can't encode 0, Inf, NaN, -0 via tuples)
    erlang_cases = [
        make_real(1.0),
        make_real(2.0),
        make_real(3.0),
        make_real(-1.0),
        make_real(-2.0),
        make_real(-3.0),
        make_real(0.5),
        make_real(0.25),
        make_real(0.125),
        make_real(4.0),
        make_real(8.0),
        make_real(16.0),
        make_real(256.0),
        make_real(1024.0),
        make_real(65536.0),
        make_real(1.5),
        make_real(2.5),
        make_real(3.75),
        make_real(-0.5),
        make_real(-1.5),
        make_real(-3.75),
        make_real(10.0),
        make_real(100.0),
        make_real(1000.0),
        make_real(-10.0),
        make_real(-100.0),
        make_real(1e-10),
        make_real(1e-20),
        make_real(-1e-10),
        make_real(1e10),
        make_real(1e20),
        make_real(1e50),
        make_real(-1e10),
        make_real(-1e20),
        make_real(1e100),
        make_real(1e200),
        make_real(1e-100),
        make_real(1e-200),
        make_real(-1e100),
        make_real(3.141592653589793),
        make_real(2.718281828459045),
        make_real(-3.141592653589793),
        make_real(1.7976931348623157e308),
        make_real(-1.7976931348623157e308),
        make_real(2.2250738585072014e-308),
        make_real(5e-324),
        # Additional edge cases
        make_real(-5e-324),
        make_real(-2.2250738585072014e-308),
    ]
    for case in erlang_cases:
        value = case["value"]
        for aligned in [True, False]:
            output = encode_real_erl(value, aligned)
            results.append(
                {
                    "input": case,
                    "aligned": aligned,
                    "output": output,
                }
            )

    content = json.dumps(results, indent=2)
    with open("real.json", "w") as f:
        f.write(content)

    print(f"Generated {len(results)} real test cases")


# ---------------------------------------------------------------------------
# Erlang-based encoder (calls encode_real.erl for cross-validation).
# ---------------------------------------------------------------------------

_ERLANG_DIR_ = os.path.join(os.path.dirname(os.path.abspath(__file__)), "erlang")


def encode_real_erl(value, aligned):
    script = os.path.join(_ERLANG_DIR_, "encode_real.erl")
    cmd = ["escript", script, "-value", f"{value:.20e}"]
    if aligned:
        cmd.append("-aligned")
    result = subprocess.run(cmd, cwd=_ERLANG_DIR_, capture_output=True, text=True)
    if result.returncode != 0:
        print(
            f"Erlang encode error for REAL value={value} aligned={aligned}:",
            file=sys.stderr,
        )
        print(result.stderr, file=sys.stderr)
        sys.exit(1)
    return result.stdout.strip().lower()


if __name__ == "__main__":
    main()
