#!/usr/bin/env python3
"""
Compile BITSTRINGS.asn1 using Erlang asn1ct into aper/ and uper/ directories.
"""

import subprocess
import sys
import os

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
ASN1_MODULE = "BITSTRINGS"

ENCODINGS = [
    ("per",  os.path.join(SCRIPT_DIR, "aper")),
    ("uper", os.path.join(SCRIPT_DIR, "uper")),
]


def compile_asn1(encoding: str, outdir: str) -> bool:
    cmd = [
        "erl", "-noshell", "-eval",
        f'asn1ct:compile("{ASN1_MODULE}", [{{outdir, "{outdir}"}}, {encoding}]), halt().',
    ]
    print(f"Compiling {encoding.upper()} -> {outdir}")
    result = subprocess.run(cmd, cwd=SCRIPT_DIR, capture_output=True, text=True)
    if result.stdout:
        print(result.stdout, end="")
    if result.stderr:
        print(result.stderr, end="", file=sys.stderr)
    if result.returncode != 0:
        print(f"ERROR: {encoding.upper()} compilation failed (exit {result.returncode})", file=sys.stderr)
        return False
    print(f"OK: {encoding.upper()} compiled successfully")
    return True


def main():
    success = True
    for encoding, outdir in ENCODINGS:
        os.makedirs(outdir, exist_ok=True)
        if not compile_asn1(encoding, outdir):
            success = False
    sys.exit(0 if success else 1)


if __name__ == "__main__":
    main()
