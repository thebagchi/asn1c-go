#!/usr/bin/env python3

import json
import os
import subprocess
import sys
from binascii import hexlify

from pycrate_asn1rt.asnobj_basic import BOOL  # type: ignore


def encode_per(obj, aligned=True):
    if aligned:
        return obj.to_aper()
    else:
        return obj.to_uper()


def encode_boolean(value, aligned=True):
    obj = BOOL(name="BOOLEAN")
    obj.set_val(value)
    return encode_per(obj, aligned)


def main():
    results = []
    cases = [
        {"value": True, "aligned": True},
        {"value": True, "aligned": False},
        {"value": False, "aligned": True},
        {"value": False, "aligned": False},
    ]
    for case in cases:
        value = case["value"]
        aligned = case["aligned"]
        data = encode_boolean(value, aligned)
        output = hexlify(data).decode("ascii")
        result = {
            "input": value,
            "aligned": aligned,
            "output": output,
        }
        results.append(result)

    # --- Erlang cross-validation ---
    erlang_cases = [
        {"value": True},
        {"value": False},
    ]
    for case in erlang_cases:
        value = case["value"]
        for aligned in [True, False]:
            output = encode_boolean_erl(value, aligned)
            results.append(
                {
                    "input": value,
                    "aligned": aligned,
                    "output": output,
                }
            )

    content = json.dumps(results, indent=2)
    with open("bool.json", "w") as f:
        f.write(content)

    print(f"Generated {len(results)} boolean test cases")


# ---------------------------------------------------------------------------
# Erlang-based encoder (calls encode_boolean.erl for cross-validation).
# ---------------------------------------------------------------------------

_ERLANG_DIR_ = os.path.join(os.path.dirname(os.path.abspath(__file__)), "erlang")


def encode_boolean_erl(value, aligned):
    script = os.path.join(_ERLANG_DIR_, "encode_boolean.erl")
    cmd = ["escript", script, "-value", "true" if value else "false"]
    if aligned:
        cmd.append("-aligned")
    result = subprocess.run(cmd, cwd=_ERLANG_DIR_, capture_output=True, text=True)
    if result.returncode != 0:
        print(
            f"Erlang encode error for BOOL value={value} aligned={aligned}:",
            file=sys.stderr,
        )
        print(result.stderr, file=sys.stderr)
        sys.exit(1)
    return result.stdout.strip().lower()


if __name__ == "__main__":
    main()
