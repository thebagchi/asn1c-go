#!/usr/bin/env python3
"""Generate cross-validated PER test vectors for MinutesEncoding
(lib/builtin/minutes_encoding.go).

X.691 (02/2021) clause 32.3:

    MINUTES-ENCODING ::= SEQUENCE {
        hours   INTEGER (0..24), -- 5 bits
        minutes INTEGER (0..59)  -- 5 bits
    }

Uses pycrate (compiling TIME-DIFFERENCE.asn1 directly, the same file
Erlang's asn1ct compiles) as the primary reference, and cross-validates
every case against Erlang/OTP's asn1 compiler via
encode_minutes_encoding.erl.
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
GENERATED_PY = "/tmp/minutes_encoding_gen.py"


def load_minutes_encoding():
    """Compile TIME-DIFFERENCE.asn1 via pycrate and return the MINUTES-ENCODING class."""
    with open(ASN1_SOURCE) as f:
        text = f.read()
    compile_text(text)
    generate_modules(PycrateGenerator, GENERATED_PY)

    spec = importlib.util.spec_from_file_location("minutes_encoding_gen", GENERATED_PY)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod.TIME_DIFFERENCE.MINUTES_ENCODING


def encode_minutes_encoding(obj, hours, minutes, aligned=True):
    obj.set_val({"hours": hours, "minutes": minutes})
    return obj.to_aper() if aligned else obj.to_uper()


def main():
    obj = load_minutes_encoding()
    results = []

    cases = [
        (0, 0),
        (12, 30),
        (24, 59),
        (1, 1),
        (23, 0),
    ]

    for hours, minutes in cases:
        for aligned in [True, False]:
            data = encode_minutes_encoding(obj, hours, minutes, aligned)
            output = hexlify(data).decode("ascii")
            results.append(
                {
                    "input": {"hours": hours, "minutes": minutes},
                    "aligned": aligned,
                    "output": output,
                }
            )

    # --- Erlang cross-validation (all cases) ---
    for hours, minutes in cases:
        for aligned in [True, False]:
            output = encode_minutes_encoding_erl(hours, minutes, aligned)
            results.append(
                {
                    "input": {"hours": hours, "minutes": minutes},
                    "aligned": aligned,
                    "output": output,
                }
            )

    content = json.dumps(results, indent=2)
    with open(os.path.join(SCRIPT_DIR, "minutes_encoding.json"), "w") as f:
        f.write(content)

    print(f"Generated {len(results)} MinutesEncoding test cases")


# ---------------------------------------------------------------------------
# Erlang-based encoder (calls encode_minutes_encoding.erl for cross-validation).
# ---------------------------------------------------------------------------

_ERLANG_DIR_ = os.path.join(SCRIPT_DIR, "erlang")


def encode_minutes_encoding_erl(hours, minutes, aligned):
    script = os.path.join(_ERLANG_DIR_, "encode_minutes_encoding.erl")
    cmd = ["escript", script, "-hours", str(hours), "-minutes", str(minutes)]
    if aligned:
        cmd.append("-aligned")
    result = subprocess.run(cmd, cwd=_ERLANG_DIR_, capture_output=True, text=True)
    if result.returncode != 0:
        print(
            f"Erlang encode error for MinutesEncoding hours={hours} minutes={minutes} "
            f"aligned={aligned}:",
            file=sys.stderr,
        )
        print(result.stderr, file=sys.stderr)
        sys.exit(1)
    return result.stdout.strip().lower()


if __name__ == "__main__":
    main()
