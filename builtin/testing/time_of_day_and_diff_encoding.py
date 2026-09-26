#!/usr/bin/env python3
"""Generate cross-validated PER test vectors for TimeOfDayAndDiffEncoding
(lib/builtin/time_of_day_and_diff_encoding.go).

X.691 (02/2021) clause 32.3:

    TIME-OF-DAY-AND-DIFF-ENCODING ::= SEQUENCE {
        local-time SEQUENCE {
            hours   INTEGER (0..24),
            minutes INTEGER (0..59),
            seconds INTEGER (0..60)
        },
        time-difference TIME-DIFFERENCE
    }

Uses pycrate (compiling TIME-DIFFERENCE.asn1 directly, the same file
Erlang's asn1ct compiles) as the primary reference, and cross-validates
every case against Erlang/OTP's asn1 compiler via
encode_time_of_day_and_diff_encoding.erl.
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
GENERATED_PY = "/tmp/time_of_day_and_diff_encoding_gen.py"


def load_time_of_day_and_diff_encoding():
    """Compile TIME-DIFFERENCE.asn1 via pycrate and return the TIME-OF-DAY-AND-DIFF-ENCODING class."""
    with open(ASN1_SOURCE) as f:
        text = f.read()
    compile_text(text)
    generate_modules(PycrateGenerator, GENERATED_PY)

    spec = importlib.util.spec_from_file_location("time_of_day_and_diff_encoding_gen", GENERATED_PY)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod.TIME_DIFFERENCE.TIME_OF_DAY_AND_DIFF_ENCODING


def encode_time_of_day_and_diff_encoding(obj, hours, minutes, seconds, sign, diff_hours, diff_minutes, aligned=True):
    td = {"sign": sign, "hours": diff_hours}
    if diff_minutes is not None:
        td["minutes"] = diff_minutes
    obj.set_val({
        "local-time": {"hours": hours, "minutes": minutes, "seconds": seconds},
        "time-difference": td,
    })
    return obj.to_aper() if aligned else obj.to_uper()


def main():
    obj = load_time_of_day_and_diff_encoding()
    results = []

    cases = [
        # (hours, minutes, seconds, sign, diff_hours, diff_minutes)
        (0, 0, 0, "positive", 0, None),
        (24, 59, 60, "negative", 15, None),
        (12, 30, 30, "positive", 5, 30),
        (1, 1, 1, "negative", 0, 1),
        (23, 15, 45, "positive", 12, 59),
    ]

    for hours, minutes, seconds, sign, diff_hours, diff_minutes in cases:
        for aligned in [True, False]:
            data = encode_time_of_day_and_diff_encoding(
                obj, hours, minutes, seconds, sign, diff_hours, diff_minutes, aligned
            )
            output = hexlify(data).decode("ascii")
            results.append(
                {
                    "input": {
                        "hours": hours,
                        "minutes": minutes,
                        "seconds": seconds,
                        "sign": sign,
                        "diff_hours": diff_hours,
                        "diff_minutes": diff_minutes,
                    },
                    "aligned": aligned,
                    "output": output,
                }
            )

    # --- Erlang cross-validation (all cases) ---
    for hours, minutes, seconds, sign, diff_hours, diff_minutes in cases:
        for aligned in [True, False]:
            output = encode_time_of_day_and_diff_encoding_erl(
                hours, minutes, seconds, sign, diff_hours, diff_minutes, aligned
            )
            results.append(
                {
                    "input": {
                        "hours": hours,
                        "minutes": minutes,
                        "seconds": seconds,
                        "sign": sign,
                        "diff_hours": diff_hours,
                        "diff_minutes": diff_minutes,
                    },
                    "aligned": aligned,
                    "output": output,
                }
            )

    content = json.dumps(results, indent=2)
    with open(os.path.join(SCRIPT_DIR, "time_of_day_and_diff_encoding.json"), "w") as f:
        f.write(content)

    print(f"Generated {len(results)} TimeOfDayAndDiffEncoding test cases")


# ---------------------------------------------------------------------------
# Erlang-based encoder (calls encode_time_of_day_and_diff_encoding.erl for cross-validation).
# ---------------------------------------------------------------------------

_ERLANG_DIR_ = os.path.join(SCRIPT_DIR, "erlang")


def encode_time_of_day_and_diff_encoding_erl(hours, minutes, seconds, sign, diff_hours, diff_minutes, aligned):
    script = os.path.join(_ERLANG_DIR_, "encode_time_of_day_and_diff_encoding.erl")
    cmd = [
        "escript", script,
        "-hours", str(hours),
        "-minutes", str(minutes),
        "-seconds", str(seconds),
        "-sign", sign,
        "-diff-hours", str(diff_hours),
    ]
    if diff_minutes is not None:
        cmd += ["-diff-minutes", str(diff_minutes)]
    if aligned:
        cmd.append("-aligned")
    result = subprocess.run(cmd, cwd=_ERLANG_DIR_, capture_output=True, text=True)
    if result.returncode != 0:
        print(
            f"Erlang encode error for TimeOfDayAndDiffEncoding hours={hours} minutes={minutes} "
            f"seconds={seconds} sign={sign} diff_hours={diff_hours} diff_minutes={diff_minutes} "
            f"aligned={aligned}:",
            file=sys.stderr,
        )
        print(result.stderr, file=sys.stderr)
        sys.exit(1)
    return result.stdout.strip().lower()


if __name__ == "__main__":
    main()
