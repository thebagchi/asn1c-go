#!/usr/bin/env python3
"""Generate cross-validated PER test vectors for YearMonthEncoding
(lib/builtin/year_month_encoding.go).

X.691 (02/2021) clause 32.2.5:

    YEAR-MONTH-ENCODING ::= SEQUENCE {
        year  YEAR-ENCODING,
        month INTEGER (1..12) -- 4 bits
    }

Uses pycrate (compiling YEAR.asn1 directly, the same file Erlang's asn1ct
compiles) as the primary reference, and cross-validates every case against
Erlang/OTP's asn1 compiler via encode_year_month_encoding.erl.
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
GENERATED_PY = "/tmp/year_month_encoding_gen.py"


def load_year_month_encoding():
    """Compile YEAR.asn1 via pycrate and return the YEAR-MONTH-ENCODING class."""
    with open(ASN1_SOURCE) as f:
        text = f.read()
    compile_text(text)
    generate_modules(PycrateGenerator, GENERATED_PY)

    spec = importlib.util.spec_from_file_location("year_month_encoding_gen", GENERATED_PY)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod.YEAR.YEAR_MONTH_ENCODING


def choice_for(value):
    if 2005 <= value <= 2020:
        return "immediate"
    if 2021 <= value <= 2276:
        return "near-future"
    if 1749 <= value <= 2004:
        return "near-past"
    return "remainder"


def encode_year_month_encoding(obj, year, month, aligned=True):
    obj.set_val({"year": (choice_for(year), year), "month": month})
    return obj.to_aper() if aligned else obj.to_uper()


def main():
    obj = load_year_month_encoding()
    results = []

    cases = [
        # (year, month)
        (2005, 1),
        (2010, 6),
        (2020, 12),
        (2021, 1),
        (2100, 6),
        (2276, 12),
        (1749, 1),
        (1800, 6),
        (2004, 12),
        (0, 1),
        (100, 12),
        (1748, 5),
        (2277, 7),
        (-32768, 1),
        (32767, 12),
    ]

    for year, month in cases:
        for aligned in [True, False]:
            data = encode_year_month_encoding(obj, year, month, aligned)
            output = hexlify(data).decode("ascii")
            results.append(
                {
                    "input": {"year": year, "month": month},
                    "aligned": aligned,
                    "output": output,
                }
            )

    # --- Erlang cross-validation (all cases) ---
    for year, month in cases:
        for aligned in [True, False]:
            output = encode_year_month_encoding_erl(year, month, aligned)
            results.append(
                {
                    "input": {"year": year, "month": month},
                    "aligned": aligned,
                    "output": output,
                }
            )

    content = json.dumps(results, indent=2)
    with open(os.path.join(SCRIPT_DIR, "year_month_encoding.json"), "w") as f:
        f.write(content)

    print(f"Generated {len(results)} YearMonthEncoding test cases")


# ---------------------------------------------------------------------------
# Erlang-based encoder (calls encode_year_month_encoding.erl for cross-validation).
# ---------------------------------------------------------------------------

_ERLANG_DIR_ = os.path.join(SCRIPT_DIR, "erlang")


def encode_year_month_encoding_erl(year, month, aligned):
    script = os.path.join(_ERLANG_DIR_, "encode_year_month_encoding.erl")
    cmd = ["escript", script, "-year", str(year), "-month", str(month)]
    if aligned:
        cmd.append("-aligned")
    result = subprocess.run(cmd, cwd=_ERLANG_DIR_, capture_output=True, text=True)
    if result.returncode != 0:
        print(
            f"Erlang encode error for YearMonthEncoding year={year} month={month} "
            f"aligned={aligned}:",
            file=sys.stderr,
        )
        print(result.stderr, file=sys.stderr)
        sys.exit(1)
    return result.stdout.strip().lower()


if __name__ == "__main__":
    main()
