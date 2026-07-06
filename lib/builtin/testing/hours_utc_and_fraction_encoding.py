#!/usr/bin/env python3
"""Generate cross-validated PER test vectors for HoursUtcAndFractionEncoding
(lib/builtin/hours_utc_and_fraction_encoding.go).

X.691 (02/2021) clause 32.3:

    HOURS-UTC-AND-FRACTION-ENCODING ::= SEQUENCE {
        hours    INTEGER (0..24), -- 5 bits
        fraction INTEGER (0..999, ..., 1000..MAX) -- 11 bits for up to 3-digit accuracy
    }

Uses pycrate (compiling TIME-DIFFERENCE.asn1 directly, the same file
Erlang's asn1ct compiles) as the primary reference, and cross-validates
every case against Erlang/OTP's asn1 compiler via
encode_hours_utc_and_fraction_encoding.erl.
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
GENERATED_PY = "/tmp/hours_utc_and_fraction_encoding_gen.py"


def load_hours_utc_and_fraction_encoding():
    """Compile TIME-DIFFERENCE.asn1 via pycrate and return the HOURS-UTC-AND-FRACTION-ENCODING class."""
    with open(ASN1_SOURCE) as f:
        text = f.read()
    compile_text(text)
    generate_modules(PycrateGenerator, GENERATED_PY)

    spec = importlib.util.spec_from_file_location("hours_utc_and_fraction_encoding_gen", GENERATED_PY)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod.TIME_DIFFERENCE.HOURS_UTC_AND_FRACTION_ENCODING


def encode_hours_utc_and_fraction_encoding(obj, hours, fraction, aligned=True):
    obj.set_val({"hours": hours, "fraction": fraction})
    return obj.to_aper() if aligned else obj.to_uper()


def main():
    obj = load_hours_utc_and_fraction_encoding()
    results = []

    cases = [
        (0, 0),
        (12, 500),
        (24, 999),
        (1, 1000),
        (23, 123456),
    ]

    for hours, fraction in cases:
        for aligned in [True, False]:
            data = encode_hours_utc_and_fraction_encoding(obj, hours, fraction, aligned)
            output = hexlify(data).decode("ascii")
            results.append(
                {
                    "input": {"hours": hours, "fraction": fraction},
                    "aligned": aligned,
                    "output": output,
                }
            )

    # --- Erlang cross-validation (all cases) ---
    for hours, fraction in cases:
        for aligned in [True, False]:
            output = encode_hours_utc_and_fraction_encoding_erl(hours, fraction, aligned)
            results.append(
                {
                    "input": {"hours": hours, "fraction": fraction},
                    "aligned": aligned,
                    "output": output,
                }
            )

    content = json.dumps(results, indent=2)
    with open(os.path.join(SCRIPT_DIR, "hours_utc_and_fraction_encoding.json"), "w") as f:
        f.write(content)

    print(f"Generated {len(results)} HoursUtcAndFractionEncoding test cases")


# ---------------------------------------------------------------------------
# Erlang-based encoder (calls encode_hours_utc_and_fraction_encoding.erl for cross-validation).
# ---------------------------------------------------------------------------

_ERLANG_DIR_ = os.path.join(SCRIPT_DIR, "erlang")


def encode_hours_utc_and_fraction_encoding_erl(hours, fraction, aligned):
    script = os.path.join(_ERLANG_DIR_, "encode_hours_utc_and_fraction_encoding.erl")
    cmd = ["escript", script, "-hours", str(hours), "-fraction", str(fraction)]
    if aligned:
        cmd.append("-aligned")
    result = subprocess.run(cmd, cwd=_ERLANG_DIR_, capture_output=True, text=True)
    if result.returncode != 0:
        print(
            f"Erlang encode error for HoursUtcAndFractionEncoding hours={hours} "
            f"fraction={fraction} aligned={aligned}:",
            file=sys.stderr,
        )
        print(result.stderr, file=sys.stderr)
        sys.exit(1)
    return result.stdout.strip().lower()


if __name__ == "__main__":
    main()
