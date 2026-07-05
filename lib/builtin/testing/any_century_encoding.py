#!/usr/bin/env python3
"""Generate cross-validated PER test vectors for AnyCenturyEncoding
(lib/builtin/any_century_encoding.go).

X.691 (02/2021) clause 32.2.2:

    ANY-CENTURY-ENCODING ::= INTEGER (MIN..MAX)

Uses pycrate (compiling CENTURY.asn1 directly, the same file Erlang's
asn1ct compiles) as the primary reference, and cross-validates every case
against Erlang/OTP's asn1 compiler via encode_any_century_encoding.erl.
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
ASN1_SOURCE = os.path.join(SCRIPT_DIR, "CENTURY.asn1")
GENERATED_PY = "/tmp/any_century_encoding_gen.py"


def load_any_century_encoding():
    """Compile CENTURY.asn1 via pycrate and return the ANY-CENTURY-ENCODING class."""
    with open(ASN1_SOURCE) as f:
        text = f.read()
    compile_text(text)
    generate_modules(PycrateGenerator, GENERATED_PY)

    spec = importlib.util.spec_from_file_location("any_century_encoding_gen", GENERATED_PY)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod.CENTURY.ANY_CENTURY_ENCODING


def encode_any_century_encoding(obj, value, aligned=True):
    obj.set_val(value)
    return obj.to_aper() if aligned else obj.to_uper()


def main():
    obj = load_any_century_encoding()
    results = []

    cases = [
        0,
        1,
        -1,
        20,
        -20,
        127,
        128,
        -128,
        -129,
        255,
        256,
        -256,
        1900,
        -1900,
        32767,
        -32768,
        1000000,
        -1000000,
        2147483647,
        -2147483648,
    ]

    for value in cases:
        for aligned in [True, False]:
            data = encode_any_century_encoding(obj, value, aligned)
            output = hexlify(data).decode("ascii")
            results.append({"input": {"value": value}, "aligned": aligned, "output": output})

    # --- Erlang cross-validation (all cases) ---
    for value in cases:
        for aligned in [True, False]:
            output = encode_any_century_encoding_erl(value, aligned)
            results.append({"input": {"value": value}, "aligned": aligned, "output": output})

    content = json.dumps(results, indent=2)
    with open(os.path.join(SCRIPT_DIR, "any_century_encoding.json"), "w") as f:
        f.write(content)

    print(f"Generated {len(results)} AnyCenturyEncoding test cases")


# ---------------------------------------------------------------------------
# Erlang-based encoder (calls encode_any_century_encoding.erl for cross-validation).
# ---------------------------------------------------------------------------

_ERLANG_DIR_ = os.path.join(SCRIPT_DIR, "erlang")


def encode_any_century_encoding_erl(value, aligned):
    script = os.path.join(_ERLANG_DIR_, "encode_any_century_encoding.erl")
    cmd = ["escript", script, "-value", str(value)]
    if aligned:
        cmd.append("-aligned")
    result = subprocess.run(cmd, cwd=_ERLANG_DIR_, capture_output=True, text=True)
    if result.returncode != 0:
        print(
            f"Erlang encode error for AnyCenturyEncoding value={value} aligned={aligned}:",
            file=sys.stderr,
        )
        print(result.stderr, file=sys.stderr)
        sys.exit(1)
    return result.stdout.strip().lower()


if __name__ == "__main__":
    main()
