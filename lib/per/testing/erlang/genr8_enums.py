#!/usr/bin/env python3
"""Generate ENUMERATEDS.asn1 with prettified formatting.

Each enum member appears on its own line with 4-space indentation.
The closing brace is on its own line without indentation.

Usage:
    python genr8_enums.py          # writes ENUMERATEDS.asn1 in same directory
    python genr8_enums.py --check  # verify existing file matches (exit 1 if stale)
"""

import os
import sys

# Non-extensible root counts
NON_EXTENSIBLE_COUNTS = [2, 3, 4, 5, 6, 7, 8, 9, 10, 15, 16, 17, 33, 65, 128, 129, 255, 256]

# Extensible: (root_count, ext_count)
EXTENSIBLE_TYPES = [
    (1, 1),
    (2, 2),
    (3, 2),
    (4, 256),
    (7, 2),
    (17, 2),
    (128, 4),
    (129, 2),
]

# --------------------------------------------------------------------------
# Templates
# --------------------------------------------------------------------------

HEADER = "ENUMERATEDS DEFINITIONS AUTOMATIC TAGS ::= BEGIN"
FOOTER = "END"

NON_EXT_TPL = """\
ENUM-{root}-0-FALSE ::= ENUMERATED {{
{members}
}}"""

EXT_TPL = """\
ENUM-{root}-{ext}-TRUE ::= ENUMERATED {{
{root_members},
    ...,
{ext_members}
}}"""


def comma_sep_members(start, count):
    """Return indented member lines joined with commas (last has no comma)."""
    return ",\n".join(f"    m-{i}" for i in range(start, start + count))


def generate():
    """Return the full ENUMERATEDS.asn1 content."""
    blocks = [HEADER, ""]

    for c in NON_EXTENSIBLE_COUNTS:
        blocks.append(NON_EXT_TPL.format(root=c, members=comma_sep_members(1, c)))
        blocks.append("")

    for root, ext in EXTENSIBLE_TYPES:
        blocks.append(
            EXT_TPL.format(
                root=root,
                ext=ext,
                root_members=comma_sep_members(1, root),
                ext_members=comma_sep_members(root + 1, ext),
            )
        )
        blocks.append("")

    blocks.append(FOOTER)
    blocks.append("")
    return "\n".join(blocks)


def main():
    script_dir = os.path.dirname(os.path.abspath(__file__))
    out_path = os.path.join(script_dir, "ENUMERATEDS.asn1")

    content = generate()

    if "--check" in sys.argv:
        with open(out_path) as f:
            existing = f.read()
        if existing == content:
            print("ENUMERATEDS.asn1 is up to date")
        else:
            print("ENUMERATEDS.asn1 is STALE — re-run genr8_enums.py", file=sys.stderr)
            sys.exit(1)
        return

    with open(out_path, "w") as f:
        f.write(content)
    print(f"Wrote {out_path}")


if __name__ == "__main__":
    main()
