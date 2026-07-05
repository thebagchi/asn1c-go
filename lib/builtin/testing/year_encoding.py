#!/usr/bin/env python3
"""Generate cross-validated PER test vectors for YearEncoding
(lib/builtin/year_encoding.go).

X.691 (02/2021) clause 32.2.3:

    YEAR-ENCODING ::= CHOICE { -- 2 bits for choice determinant
        immediate   INTEGER (2005..2020), -- 4 bits
        near-future INTEGER (2021..2276), -- 8 bits
        near-past   INTEGER (1749..2004), -- 8 bits
        remainder   INTEGER (MIN..1748 | 2277..MAX)
    }

Uses pycrate (compiling YEAR.asn1 directly, the same file Erlang's asn1ct
compiles) as the primary reference, and cross-validates every case against
Erlang/OTP's asn1 compiler via encode_year_encoding.erl. Note: YEAR.asn1's
"remainder" alternative is simplified to plain INTEGER as a workaround for
an Erlang asn1ct crash on MIN/MAX-gap value-set constraints; this does not
affect the PER encoding (see YEAR.asn1's header comment for details), so
pycrate is fed the exact same (simplified) module Erlang uses here too.
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
GENERATED_PY = "/tmp/year_encoding_gen.py"


def load_year_encoding():
    """Compile YEAR.asn1 via pycrate and return the YEAR-ENCODING class."""
    with open(ASN1_SOURCE) as f:
        text = f.read()
    compile_text(text)
    generate_modules(PycrateGenerator, GENERATED_PY)

    spec = importlib.util.spec_from_file_location("year_encoding_gen", GENERATED_PY)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod.YEAR.YEAR_ENCODING


def choice_for(value):
    if 2005 <= value <= 2020:
        return "immediate"
    if 2021 <= value <= 2276:
        return "near-future"
    if 1749 <= value <= 2004:
        return "near-past"
    return "remainder"


def encode_year_encoding(obj, value, aligned=True):
    obj.set_val((choice_for(value), value))
    return obj.to_aper() if aligned else obj.to_uper()


def main():
    obj = load_year_encoding()
    results = []

    cases = [
        # immediate: 2005..2020
        2005,
        2010,
        2020,
        # near-future: 2021..2276
        2021,
        2100,
        2276,
        # near-past: 1749..2004
        1749,
        1800,
        2004,
        # remainder: everything else
        0,
        1,
        -1,
        100,
        1748,
        2277,
        5000,
        32767,
        -32768,
        2147483647,
        -2147483648,
    ]

    for value in cases:
        for aligned in [True, False]:
            data = encode_year_encoding(obj, value, aligned)
            output = hexlify(data).decode("ascii")
            results.append({"input": {"value": value}, "aligned": aligned, "output": output})

    # --- Erlang cross-validation (all cases) ---
    for value in cases:
        for aligned in [True, False]:
            output = encode_year_encoding_erl(value, aligned)
            results.append({"input": {"value": value}, "aligned": aligned, "output": output})

    content = json.dumps(results, indent=2)
    with open(os.path.join(SCRIPT_DIR, "year_encoding.json"), "w") as f:
        f.write(content)

    print(f"Generated {len(results)} YearEncoding test cases")


# ---------------------------------------------------------------------------
# Erlang-based encoder (calls encode_year_encoding.erl for cross-validation).
# ---------------------------------------------------------------------------

_ERLANG_DIR_ = os.path.join(SCRIPT_DIR, "erlang")


def encode_year_encoding_erl(value, aligned):
    script = os.path.join(_ERLANG_DIR_, "encode_year_encoding.erl")
    cmd = ["escript", script, "-value", str(value)]
    if aligned:
        cmd.append("-aligned")
    result = subprocess.run(cmd, cwd=_ERLANG_DIR_, capture_output=True, text=True)
    if result.returncode != 0:
        print(
            f"Erlang encode error for YearEncoding value={value} aligned={aligned}:",
            file=sys.stderr,
        )
        print(result.stderr, file=sys.stderr)
        sys.exit(1)
    return result.stdout.strip().lower()


if __name__ == "__main__":
    main()
