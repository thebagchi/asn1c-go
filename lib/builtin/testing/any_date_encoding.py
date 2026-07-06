#!/usr/bin/env python3
"""Generate cross-validated PER test vectors for AnyDateEncoding
(lib/builtin/any_date_encoding.go).

X.691 (02/2021) clause 32.2.7:

    ANY-DATE-ENCODING ::= SEQUENCE {
        year  ANY-YEAR-ENCODING,
        month INTEGER (1..12),
        day   INTEGER (1..31)
    }

Uses pycrate (compiling YEAR.asn1 directly, the same file Erlang's asn1ct
compiles) as the primary reference, and cross-validates every case against
Erlang/OTP's asn1 compiler via encode_any_date_encoding.erl.
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
GENERATED_PY = "/tmp/any_date_encoding_gen.py"


def load_any_date_encoding():
    """Compile YEAR.asn1 via pycrate and return the ANY-DATE-ENCODING class."""
    with open(ASN1_SOURCE) as f:
        text = f.read()
    compile_text(text)
    generate_modules(PycrateGenerator, GENERATED_PY)

    spec = importlib.util.spec_from_file_location("any_date_encoding_gen", GENERATED_PY)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod.YEAR.ANY_DATE_ENCODING


def encode_any_date_encoding(obj, year, month, day, aligned=True):
    obj.set_val({"year": year, "month": month, "day": day})
    return obj.to_aper() if aligned else obj.to_uper()


def main():
    obj = load_any_date_encoding()
    results = []

    cases = [
        # (year, month, day)
        (2005, 1, 1),
        (2010, 6, 15),
        (2020, 12, 31),
        (2021, 1, 1),
        (2100, 6, 15),
        (2276, 12, 31),
        (1749, 1, 1),
        (1800, 6, 15),
        (2004, 12, 31),
        (0, 1, 1),
        (100, 12, 31),
        (1748, 5, 20),
        (2277, 7, 4),
        (-32768, 1, 1),
        (32767, 12, 31),
    ]

    for year, month, day in cases:
        for aligned in [True, False]:
            data = encode_any_date_encoding(obj, year, month, day, aligned)
            output = hexlify(data).decode("ascii")
            results.append(
                {
                    "input": {"year": year, "month": month, "day": day},
                    "aligned": aligned,
                    "output": output,
                }
            )

    # --- Erlang cross-validation (all cases) ---
    for year, month, day in cases:
        for aligned in [True, False]:
            output = encode_any_date_encoding_erl(year, month, day, aligned)
            results.append(
                {
                    "input": {"year": year, "month": month, "day": day},
                    "aligned": aligned,
                    "output": output,
                }
            )

    content = json.dumps(results, indent=2)
    with open(os.path.join(SCRIPT_DIR, "any_date_encoding.json"), "w") as f:
        f.write(content)

    print(f"Generated {len(results)} AnyDateEncoding test cases")


# ---------------------------------------------------------------------------
# Erlang-based encoder (calls encode_any_date_encoding.erl for cross-validation).
# ---------------------------------------------------------------------------

_ERLANG_DIR_ = os.path.join(SCRIPT_DIR, "erlang")


def encode_any_date_encoding_erl(year, month, day, aligned):
    script = os.path.join(_ERLANG_DIR_, "encode_any_date_encoding.erl")
    cmd = ["escript", script, "-year", str(year), "-month", str(month), "-day", str(day)]
    if aligned:
        cmd.append("-aligned")
    result = subprocess.run(cmd, cwd=_ERLANG_DIR_, capture_output=True, text=True)
    if result.returncode != 0:
        print(
            f"Erlang encode error for AnyDateEncoding year={year} month={month} day={day} "
            f"aligned={aligned}:",
            file=sys.stderr,
        )
        print(result.stderr, file=sys.stderr)
        sys.exit(1)
    return result.stdout.strip().lower()


if __name__ == "__main__":
    main()
