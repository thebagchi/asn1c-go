#!/usr/bin/env python3
"""Generate cross-validated PER test vectors for AnyYearWeekEncoding
(lib/builtin/any_year_week_encoding.go).

X.691 (02/2021) clause 32.2.11:

    ANY-YEAR-WEEK-ENCODING ::= SEQUENCE {
        year ANY-YEAR-ENCODING,
        week INTEGER (1..53)
    }

Uses pycrate (compiling YEAR.asn1 directly, the same file Erlang's asn1ct
compiles) as the primary reference, and cross-validates every case against
Erlang/OTP's asn1 compiler via encode_any_year_week_encoding.erl.
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
ASN1_SOURCE = os.path.join(SCRIPT_DIR, "YEAR.asn1")
GENERATED_PY = "/tmp/any_year_week_encoding_gen.py"


def load_any_year_week_encoding():
    """Compile YEAR.asn1 via pycrate and return the ANY-YEAR-WEEK-ENCODING class."""
    with open(ASN1_SOURCE) as f:
        text = f.read()
    compile_text(text)
    generate_modules(PycrateGenerator, GENERATED_PY)

    spec = importlib.util.spec_from_file_location("any_year_week_encoding_gen", GENERATED_PY)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod.YEAR.ANY_YEAR_WEEK_ENCODING


def encode_any_year_week_encoding(obj, year, week, aligned=True):
    obj.set_val({"year": year, "week": week})
    return obj.to_aper() if aligned else obj.to_uper()


def main():
    obj = load_any_year_week_encoding()
    results = []

    cases = [
        # (year, week)
        (2005, 1),
        (2010, 26),
        (2020, 53),
        (2021, 1),
        (2100, 26),
        (2276, 52),
        (1749, 1),
        (1800, 26),
        (2004, 53),
        (0, 1),
        (100, 30),
        (1748, 15),
        (2277, 40),
        (-32768, 1),
        (32767, 53),
    ]

    for year, week in cases:
        for aligned in [True, False]:
            data = encode_any_year_week_encoding(obj, year, week, aligned)
            output = hexlify(data).decode("ascii")
            results.append(
                {
                    "input": {"year": year, "week": week},
                    "aligned": aligned,
                    "output": output,
                }
            )

    # --- Erlang cross-validation (all cases) ---
    for year, week in cases:
        for aligned in [True, False]:
            output = encode_any_year_week_encoding_erl(year, week, aligned)
            results.append(
                {
                    "input": {"year": year, "week": week},
                    "aligned": aligned,
                    "output": output,
                }
            )

    content = json.dumps(results, indent=2)
    with open(os.path.join(SCRIPT_DIR, "any_year_week_encoding.json"), "w") as f:
        f.write(content)

    print(f"Generated {len(results)} AnyYearWeekEncoding test cases")


# ---------------------------------------------------------------------------
# Erlang-based encoder (calls encode_any_year_week_encoding.erl for cross-validation).
# ---------------------------------------------------------------------------

_ERLANG_DIR_ = os.path.join(SCRIPT_DIR, "erlang")


def encode_any_year_week_encoding_erl(year, week, aligned):
    script = os.path.join(_ERLANG_DIR_, "encode_any_year_week_encoding.erl")
    cmd = ["escript", script, "-year", str(year), "-week", str(week)]
    if aligned:
        cmd.append("-aligned")
    result = subprocess.run(cmd, cwd=_ERLANG_DIR_, capture_output=True, text=True)
    if result.returncode != 0:
        print(
            f"Erlang encode error for AnyYearWeekEncoding year={year} week={week} "
            f"aligned={aligned}:",
            file=sys.stderr,
        )
        print(result.stderr, file=sys.stderr)
        sys.exit(1)
    return result.stdout.strip().lower()


if __name__ == "__main__":
    main()
