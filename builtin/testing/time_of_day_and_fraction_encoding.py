#!/usr/bin/env python3
"""Generate cross-validated PER test vectors for
TimeOfDayAndFractionEncoding (lib/builtin/time_of_day_and_fraction_encoding.go).

X.691 (02/2021) clause 32.3:

    TIME-OF-DAY-AND-FRACTION-ENCODING ::= SEQUENCE {
        hours    INTEGER (0..24), -- 5 bits
        minutes  INTEGER (0..59), -- 5 bits
        seconds  INTEGER (0..60), -- 5 bits
        fraction INTEGER (0..999, ..., 1000..MAX) -- 11 bits for up to 3-digit accuracy
    }

Uses pycrate (compiling TIME-DIFFERENCE.asn1 directly, the same file
Erlang's asn1ct compiles) as the primary reference, and cross-validates
every case against Erlang/OTP's asn1 compiler via
encode_time_of_day_and_fraction_encoding.erl.
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
GENERATED_PY = "/tmp/time_of_day_and_fraction_encoding_gen.py"


def load_time_of_day_and_fraction_encoding():
    """Compile TIME-DIFFERENCE.asn1 via pycrate and return the TIME-OF-DAY-AND-FRACTION-ENCODING class."""
    with open(ASN1_SOURCE) as f:
        text = f.read()
    compile_text(text)
    generate_modules(PycrateGenerator, GENERATED_PY)

    spec = importlib.util.spec_from_file_location("time_of_day_and_fraction_encoding_gen", GENERATED_PY)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod.TIME_DIFFERENCE.TIME_OF_DAY_AND_FRACTION_ENCODING


def encode_time_of_day_and_fraction_encoding(obj, hours, minutes, seconds, fraction, aligned=True):
    obj.set_val({"hours": hours, "minutes": minutes, "seconds": seconds, "fraction": fraction})
    return obj.to_aper() if aligned else obj.to_uper()


def main():
    obj = load_time_of_day_and_fraction_encoding()
    results = []

    cases = [
        # (hours, minutes, seconds, fraction)
        (0, 0, 0, 0),
        (12, 30, 30, 500),
        (24, 59, 60, 999),
        (1, 1, 1, 1000),
        (23, 15, 45, 123456),
    ]

    for hours, minutes, seconds, fraction in cases:
        for aligned in [True, False]:
            data = encode_time_of_day_and_fraction_encoding(obj, hours, minutes, seconds, fraction, aligned)
            output = hexlify(data).decode("ascii")
            results.append(
                {
                    "input": {"hours": hours, "minutes": minutes, "seconds": seconds, "fraction": fraction},
                    "aligned": aligned,
                    "output": output,
                }
            )

    # --- Erlang cross-validation (all cases) ---
    for hours, minutes, seconds, fraction in cases:
        for aligned in [True, False]:
            output = encode_time_of_day_and_fraction_encoding_erl(hours, minutes, seconds, fraction, aligned)
            results.append(
                {
                    "input": {"hours": hours, "minutes": minutes, "seconds": seconds, "fraction": fraction},
                    "aligned": aligned,
                    "output": output,
                }
            )

    content = json.dumps(results, indent=2)
    with open(os.path.join(SCRIPT_DIR, "time_of_day_and_fraction_encoding.json"), "w") as f:
        f.write(content)

    print(f"Generated {len(results)} TimeOfDayAndFractionEncoding test cases")


# ---------------------------------------------------------------------------
# Erlang-based encoder (calls encode_time_of_day_and_fraction_encoding.erl for cross-validation).
# ---------------------------------------------------------------------------

_ERLANG_DIR_ = os.path.join(SCRIPT_DIR, "erlang")


def encode_time_of_day_and_fraction_encoding_erl(hours, minutes, seconds, fraction, aligned):
    script = os.path.join(_ERLANG_DIR_, "encode_time_of_day_and_fraction_encoding.erl")
    cmd = [
        "escript", script,
        "-hours", str(hours),
        "-minutes", str(minutes),
        "-seconds", str(seconds),
        "-fraction", str(fraction),
    ]
    if aligned:
        cmd.append("-aligned")
    result = subprocess.run(cmd, cwd=_ERLANG_DIR_, capture_output=True, text=True)
    if result.returncode != 0:
        print(
            f"Erlang encode error for TimeOfDayAndFractionEncoding hours={hours} minutes={minutes} "
            f"seconds={seconds} fraction={fraction} aligned={aligned}:",
            file=sys.stderr,
        )
        print(result.stderr, file=sys.stderr)
        sys.exit(1)
    return result.stdout.strip().lower()


if __name__ == "__main__":
    main()
