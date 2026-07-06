#!/usr/bin/env python3
"""Generate cross-validated PER test vectors for DurationIntervalEncoding
(lib/builtin/duration_interval_encoding.go).

X.691 (02/2021) clause 32.6:

    DURATION-INTERVAL-ENCODING ::= SEQUENCE { -- 8 bits for optionality
        years   INTEGER (0..31, ..., 32..MAX) OPTIONAL,
        months  INTEGER (0..15, ..., 16..MAX) OPTIONAL,
        weeks   INTEGER (0..63, ..., 64..MAX) OPTIONAL,
        days    INTEGER (0..31, ..., 32..MAX) OPTIONAL,
        hours   INTEGER (0..31, ..., 32..MAX) OPTIONAL,
        minutes INTEGER (0..63, ..., 64..MAX) OPTIONAL,
        seconds INTEGER (0..63, ..., 64..MAX) OPTIONAL,
        fractional-part SEQUENCE {
            number-of-digits INTEGER (1..3, ..., 4..MAX),
            fractional-value INTEGER (0..999, ..., 1000..MAX)
        } OPTIONAL
    }

Uses pycrate (compiling TIME-DIFFERENCE.asn1 directly, the same file
Erlang's asn1ct compiles) as the primary reference, and cross-validates
every case against Erlang/OTP's asn1 compiler via
encode_duration_interval_encoding.erl.
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
GENERATED_PY = "/tmp/duration_interval_encoding_gen.py"


def load_duration_interval_encoding():
    """Compile TIME-DIFFERENCE.asn1 via pycrate and return the DURATION-INTERVAL-ENCODING class."""
    with open(ASN1_SOURCE) as f:
        text = f.read()
    compile_text(text)
    generate_modules(PycrateGenerator, GENERATED_PY)

    spec = importlib.util.spec_from_file_location("duration_interval_encoding_gen", GENERATED_PY)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod.TIME_DIFFERENCE.DURATION_INTERVAL_ENCODING


def encode_duration_interval_encoding(obj, fields, aligned=True):
    val = {}
    for key, value in fields.items():
        if value is not None:
            val[key] = value
    obj.set_val(val)
    return obj.to_aper() if aligned else obj.to_uper()


def main():
    obj = load_duration_interval_encoding()
    results = []

    cases = [
        # all absent
        {},
        # all present, small values
        {
            "years": 1, "months": 2, "weeks": 3, "days": 4,
            "hours": 5, "minutes": 6, "seconds": 7,
            "fractional-part": {"number-of-digits": 2, "fractional-value": 50},
        },
        # all present, root-boundary values
        {
            "years": 31, "months": 15, "weeks": 63, "days": 31,
            "hours": 31, "minutes": 63, "seconds": 63,
            "fractional-part": {"number-of-digits": 3, "fractional-value": 999},
        },
        # all present, extension values (beyond root range)
        {
            "years": 32, "months": 16, "weeks": 64, "days": 32,
            "hours": 32, "minutes": 64, "seconds": 64,
            "fractional-part": {"number-of-digits": 4, "fractional-value": 1000},
        },
        # only weeks present (canonical "weeks-only" duration)
        {"weeks": 10},
        # only seconds present (least-significant only)
        {"seconds": 0},
        # years and fractional-part only
        {"years": 5, "fractional-part": {"number-of-digits": 1, "fractional-value": 0}},
    ]

    for fields in cases:
        for aligned in [True, False]:
            data = encode_duration_interval_encoding(obj, fields, aligned)
            output = hexlify(data).decode("ascii")
            results.append(
                {
                    "input": fields,
                    "aligned": aligned,
                    "output": output,
                }
            )

    # --- Erlang cross-validation (all cases) ---
    for fields in cases:
        for aligned in [True, False]:
            output = encode_duration_interval_encoding_erl(fields, aligned)
            results.append(
                {
                    "input": fields,
                    "aligned": aligned,
                    "output": output,
                }
            )

    content = json.dumps(results, indent=2)
    with open(os.path.join(SCRIPT_DIR, "duration_interval_encoding.json"), "w") as f:
        f.write(content)

    print(f"Generated {len(results)} DurationIntervalEncoding test cases")


# ---------------------------------------------------------------------------
# Erlang-based encoder (calls encode_duration_interval_encoding.erl for cross-validation).
# ---------------------------------------------------------------------------

_ERLANG_DIR_ = os.path.join(SCRIPT_DIR, "erlang")


def encode_duration_interval_encoding_erl(fields, aligned):
    script = os.path.join(_ERLANG_DIR_, "encode_duration_interval_encoding.erl")
    cmd = ["escript", script]
    for key in ["years", "months", "weeks", "days", "hours", "minutes", "seconds"]:
        if key in fields:
            cmd += [f"-{key}", str(fields[key])]
    if "fractional-part" in fields:
        fp = fields["fractional-part"]
        cmd += ["-number-of-digits", str(fp["number-of-digits"])]
        cmd += ["-fractional-value", str(fp["fractional-value"])]
    if aligned:
        cmd.append("-aligned")
    result = subprocess.run(cmd, cwd=_ERLANG_DIR_, capture_output=True, text=True)
    if result.returncode != 0:
        print(
            f"Erlang encode error for DurationIntervalEncoding fields={fields} aligned={aligned}:",
            file=sys.stderr,
        )
        print(result.stderr, file=sys.stderr)
        sys.exit(1)
    return result.stdout.strip().lower()


if __name__ == "__main__":
    main()
