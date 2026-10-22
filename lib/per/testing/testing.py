"""Write testing.json, the one vector file of the lib/per oracle tests.

Every kind of vector has a module in this directory with KIND (the key of the
kind in testing.json) and vectors(), which returns the vectors of that kind.
The modules ask pycrate 0.8.1 and Erlang/OTP 29.1.1 through harness.py, and both
read the types of testing.asn1. This driver runs the modules in the order of
MODULES and writes the document once. With module names as arguments it runs
only those modules, prints the number of rows of each, and writes nothing.

Run: PATH=~/.local/opt/otp-29.1.1/bin:$PATH ~/.local/opt/pycrate-0.8.1/bin/python testing.py

Revisions:
  - 2026-10-20 00:06: initial creation
"""

import importlib
import sys

import harness

MODULES = [
    "bool",
    "integer",
    "unsigned",
    "enumerated",
    "real",
    "octet_string",
    "bit_string",
    "namedbits",
    "strings",
    "numeric_offset",
    "fragment",
    "additions",
    "regression",
    "iri",
    "oid",
    "relativeoid",
    "composites",
    "pdvs",
    "times",
    "held",
]


def count_rows(value):
    """Count the rows under a kind: the rows of a list, or of every list inside a dict."""
    if isinstance(value, list):
        return len(value)
    if isinstance(value, dict):
        return sum(count_rows(item) for item in value.values() if isinstance(item, (list, dict)))
    return 0


def main():
    names = sys.argv[1:] or MODULES
    document = {}
    for name in names:
        module = importlib.import_module(name)
        document[module.KIND] = module.vectors()
        print(f"{module.KIND}: {count_rows(document[module.KIND])} rows", file=sys.stderr)
    if sys.argv[1:]:
        return
    harness.write(document)


if __name__ == "__main__":
    main()
