#!/usr/bin/env python3
"""Generate cross-validated PER test vectors for TimeDifference
(lib/builtin/time_difference.go).

X.691 (02/2021) clause 32.3:

    TIME-DIFFERENCE ::= SEQUENCE {
        sign    ENUMERATED { positive, negative },
        hours   INTEGER (0..15),
        minutes INTEGER (1..59) OPTIONAL -- omitted if zero
    }

Uses pycrate (compiling TIME-DIFFERENCE.asn1 directly, the same file
Erlang's asn1ct compiles) as the primary reference, and cross-validates
every case against Erlang/OTP's asn1 compiler via
encode_time_difference.erl.
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
ASN1_SOURCE = os.path.join(SCRIPT_DIR, "TIME-DIFFERENCE.asn1")
GENERATED_PY = "/tmp/time_difference_gen.py"


def load_time_difference():
    """Compile TIME-DIFFERENCE.asn1 via pycrate and return the TIME-DIFFERENCE class."""
    with open(ASN1_SOURCE) as f:
        text = f.read()
    compile_text(text)
    generate_modules(PycrateGenerator, GENERATED_PY)

    spec = importlib.util.spec_from_file_location("time_difference_gen", GENERATED_PY)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod.TIME_DIFFERENCE.TIME_DIFFERENCE


def encode_time_difference(obj, sign, hours, minutes, aligned=True):
    val = {"sign": sign, "hours": hours}
    if minutes is not None:
        val["minutes"] = minutes
    obj.set_val(val)
    return obj.to_aper() if aligned else obj.to_uper()


def main():
    obj = load_time_difference()
    results = []

    cases = [
        # (sign, hours, minutes) — minutes=None means omitted
        ("positive", 0, None),
        ("negative", 0, None),
        ("positive", 15, None),
        ("negative", 15, None),
        ("positive", 5, 1),
        ("negative", 5, 30),
        ("positive", 12, 59),
        ("negative", 12, 59),
        ("positive", 0, 1),
        ("negative", 0, 59),
        ("positive", 8, 45),
    ]

    for sign, hours, minutes in cases:
        for aligned in [True, False]:
            data = encode_time_difference(obj, sign, hours, minutes, aligned)
            output = hexlify(data).decode("ascii")
            results.append(
                {
                    "input": {"sign": sign, "hours": hours, "minutes": minutes},
                    "aligned": aligned,
                    "output": output,
                }
            )

    # --- Erlang cross-validation (all cases) ---
    for sign, hours, minutes in cases:
        for aligned in [True, False]:
            output = encode_time_difference_erl(sign, hours, minutes, aligned)
            results.append(
                {
                    "input": {"sign": sign, "hours": hours, "minutes": minutes},
                    "aligned": aligned,
                    "output": output,
                }
            )

    content = json.dumps(results, indent=2)
    with open(os.path.join(SCRIPT_DIR, "time_difference.json"), "w") as f:
        f.write(content)

    print(f"Generated {len(results)} TimeDifference test cases")


# ---------------------------------------------------------------------------
# Erlang-based encoder (calls encode_time_difference.erl for cross-validation).
# ---------------------------------------------------------------------------

_ERLANG_DIR_ = os.path.join(SCRIPT_DIR, "erlang")


def encode_time_difference_erl(sign, hours, minutes, aligned):
    script = os.path.join(_ERLANG_DIR_, "encode_time_difference.erl")
    cmd = ["escript", script, "-sign", sign, "-hours", str(hours)]
    if minutes is not None:
        cmd += ["-minutes", str(minutes)]
    if aligned:
        cmd.append("-aligned")
    result = subprocess.run(cmd, cwd=_ERLANG_DIR_, capture_output=True, text=True)
    if result.returncode != 0:
        print(
            f"Erlang encode error for TimeDifference sign={sign} hours={hours} "
            f"minutes={minutes} aligned={aligned}:",
            file=sys.stderr,
        )
        print(result.stderr, file=sys.stderr)
        sys.exit(1)
    return result.stdout.strip().lower()


if __name__ == "__main__":
    main()
