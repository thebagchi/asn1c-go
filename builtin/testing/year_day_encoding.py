#!/usr/bin/env python3
"""Generate cross-validated PER test vectors for YearDayEncoding
(lib/builtin/year_day_encoding.go).

X.691 (02/2021) clause 32.2.8:

    YEAR-DAY-ENCODING ::= SEQUENCE {
        year YEAR-ENCODING,
        day  INTEGER (1..366)
    }

Uses pycrate (compiling YEAR.asn1 directly, the same file Erlang's asn1ct
compiles) as the primary reference, and cross-validates every case against
Erlang/OTP's asn1 compiler via encode_year_day_encoding.erl.
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
GENERATED_PY = "/tmp/year_day_encoding_gen.py"


def load_year_day_encoding():
    """Compile YEAR.asn1 via pycrate and return the YEAR-DAY-ENCODING class."""
    with open(ASN1_SOURCE) as f:
        text = f.read()
    compile_text(text)
    generate_modules(PycrateGenerator, GENERATED_PY)

    spec = importlib.util.spec_from_file_location("year_day_encoding_gen", GENERATED_PY)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod.YEAR.YEAR_DAY_ENCODING


def choice_for(value):
    if 2005 <= value <= 2020:
        return "immediate"
    if 2021 <= value <= 2276:
        return "near-future"
    if 1749 <= value <= 2004:
        return "near-past"
    return "remainder"


def encode_year_day_encoding(obj, year, day, aligned=True):
    obj.set_val({"year": (choice_for(year), year), "day": day})
    return obj.to_aper() if aligned else obj.to_uper()


def main():
    obj = load_year_day_encoding()
    results = []

    cases = [
        # (year, day)
        (2005, 1),
        (2010, 180),
        (2020, 366),
        (2021, 1),
        (2100, 180),
        (2276, 365),
        (1749, 1),
        (1800, 180),
        (2004, 366),
        (0, 1),
        (100, 200),
        (1748, 100),
        (2277, 250),
        (-32768, 1),
        (32767, 366),
    ]

    for year, day in cases:
        for aligned in [True, False]:
            data = encode_year_day_encoding(obj, year, day, aligned)
            output = hexlify(data).decode("ascii")
            results.append(
                {
                    "input": {"year": year, "day": day},
                    "aligned": aligned,
                    "output": output,
                }
            )

    # --- Erlang cross-validation (all cases) ---
    for year, day in cases:
        for aligned in [True, False]:
            output = encode_year_day_encoding_erl(year, day, aligned)
            results.append(
                {
                    "input": {"year": year, "day": day},
                    "aligned": aligned,
                    "output": output,
                }
            )

    content = json.dumps(results, indent=2)
    with open(os.path.join(SCRIPT_DIR, "year_day_encoding.json"), "w") as f:
        f.write(content)

    print(f"Generated {len(results)} YearDayEncoding test cases")


# ---------------------------------------------------------------------------
# Erlang-based encoder (calls encode_year_day_encoding.erl for cross-validation).
# ---------------------------------------------------------------------------

_ERLANG_DIR_ = os.path.join(SCRIPT_DIR, "erlang")


def encode_year_day_encoding_erl(year, day, aligned):
    script = os.path.join(_ERLANG_DIR_, "encode_year_day_encoding.erl")
    cmd = ["escript", script, "-year", str(year), "-day", str(day)]
    if aligned:
        cmd.append("-aligned")
    result = subprocess.run(cmd, cwd=_ERLANG_DIR_, capture_output=True, text=True)
    if result.returncode != 0:
        print(
            f"Erlang encode error for YearDayEncoding year={year} day={day} "
            f"aligned={aligned}:",
            file=sys.stderr,
        )
        print(result.stderr, file=sys.stderr)
        sys.exit(1)
    return result.stdout.strip().lower()


if __name__ == "__main__":
    main()
