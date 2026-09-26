#!/usr/bin/env python3
"""Generate cross-validated PER test vectors for RealType (lib/builtin/real_type.go).

RealType is X.680 clause 21.5's associated type of the REAL built-in type:

    RealType ::= SEQUENCE {
        mantissa INTEGER,
        base     INTEGER (2 | 10),
        exponent INTEGER
    }

Uses pycrate (compiling REAL-TYPE.asn1 directly, the same file Erlang's
asn1ct compiles) as the primary reference, and cross-validates a subset of
cases against Erlang/OTP's asn1 compiler via encode_real_type.erl.
"""

import importlib.util
import json
import os
import subprocess
import sys
from binascii import hexlify

from pycrate_asn1c.asnproc import compile_text, generate_modules
from pycrate_asn1c.generator import PycrateGenerator

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
ASN1_SOURCE = os.path.join(SCRIPT_DIR, "REAL-TYPE.asn1")
GENERATED_PY = "/tmp/real_type_gen.py"


def load_real_type():
    """Compile REAL-TYPE.asn1 via pycrate and return the RealType class."""
    with open(ASN1_SOURCE) as f:
        text = f.read()
    compile_text(text)
    generate_modules(PycrateGenerator, GENERATED_PY)

    spec = importlib.util.spec_from_file_location("real_type_gen", GENERATED_PY)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod.REAL_TYPE.RealType


def encode_real_type(RealType, mantissa, base, exponent, aligned=True):
    RealType.set_val({"mantissa": mantissa, "base": base, "exponent": exponent})
    return RealType.to_aper() if aligned else RealType.to_uper()


def make_case(mantissa, base, exponent):
    return {"mantissa": mantissa, "base": base, "exponent": exponent}


def main():
    RealType = load_real_type()
    results = []

    cases = [
        # Zero mantissa
        make_case(0, 2, 0),
        make_case(0, 10, 0),
        # Simple positive values
        make_case(1, 2, 0),
        make_case(3, 2, 5),
        make_case(1, 10, 0),
        make_case(3, 10, 5),
        # Negative mantissa
        make_case(-1, 2, 0),
        make_case(-3, 2, 5),
        make_case(-3, 10, 5),
        # Negative exponent
        make_case(3, 2, -5),
        make_case(3, 10, -5),
        # Negative mantissa and exponent
        make_case(-3, 2, -5),
        # Mantissa/exponent requiring multiple octets
        make_case(255, 2, 0),
        make_case(256, 2, 0),
        make_case(65535, 2, 0),
        make_case(65536, 2, 0),
        make_case(16777215, 2, 0),
        make_case(16777216, 2, 0),
        make_case(-256, 2, 0),
        make_case(-65536, 2, 0),
        make_case(-16777216, 2, 0),
        make_case(1, 2, 127),
        make_case(1, 2, 128),
        make_case(1, 2, -128),
        make_case(1, 2, -129),
        make_case(1, 2, 32767),
        make_case(1, 2, -32768),
        # Large mantissa (multi-byte, matching IEEE 754 double mantissa range)
        make_case(9007199254740993, 2, -52),  # 2^53+1, smallest non-representable-as-double odd mantissa
        make_case(-9007199254740993, 2, -52),
        # Pi-like value (odd mantissa per canonical REAL normalization)
        make_case(884279719003555, 2, -48),
    ]

    for case in cases:
        for aligned in [True, False]:
            data = encode_real_type(
                RealType, case["mantissa"], case["base"], case["exponent"], aligned
            )
            output = hexlify(data).decode("ascii")
            results.append({"input": case, "aligned": aligned, "output": output})

    # --- Erlang cross-validation (all cases) ---
    for case in cases:
        for aligned in [True, False]:
            output = encode_real_type_erl(
                case["mantissa"], case["base"], case["exponent"], aligned
            )
            results.append({"input": case, "aligned": aligned, "output": output})

    content = json.dumps(results, indent=2)
    with open(os.path.join(SCRIPT_DIR, "real_type.json"), "w") as f:
        f.write(content)

    print(f"Generated {len(results)} RealType test cases")


# ---------------------------------------------------------------------------
# Erlang-based encoder (calls encode_real_type.erl for cross-validation).
# ---------------------------------------------------------------------------

_ERLANG_DIR_ = os.path.join(SCRIPT_DIR, "erlang")


def encode_real_type_erl(mantissa, base, exponent, aligned):
    script = os.path.join(_ERLANG_DIR_, "encode_real_type.erl")
    cmd = [
        "escript",
        script,
        "-mantissa",
        str(mantissa),
        "-base",
        str(base),
        "-exponent",
        str(exponent),
    ]
    if aligned:
        cmd.append("-aligned")
    result = subprocess.run(cmd, cwd=_ERLANG_DIR_, capture_output=True, text=True)
    if result.returncode != 0:
        print(
            f"Erlang encode error for RealType mantissa={mantissa} base={base} "
            f"exponent={exponent} aligned={aligned}:",
            file=sys.stderr,
        )
        print(result.stderr, file=sys.stderr)
        sys.exit(1)
    return result.stdout.strip().lower()


if __name__ == "__main__":
    main()
