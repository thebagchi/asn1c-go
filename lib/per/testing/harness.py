"""Shared oracle helpers of the lib/per vector generators.

The ASN.1 of the oracle tests is in three files. testing.asn1 (module Testing)
holds the types that both oracles compile. testing_otp.asn1 (module TestingOtp)
holds the types that only OTP answers, and testing_pycrate.asn1 (module
TestingPycrate) the types that only pycrate answers. This file gives pycrate
0.8.1 the first and the third file, and Erlang/OTP 29.1.1 (asn1ct, per and
uper) the first and the second, compiles each once, and answers every row of
every generator from the same compiled types. The OTP build output goes to a temporary directory
that is removed at exit. To save the 30 s of the OTP build while a generator is
written, set TESTING_OTP_BUILD to a directory outside the tree: the first run
builds there and a later run reuses the build. Delete that directory after
testing.asn1 changes.

A type of testing.asn1 is named <Prefix>-<short name>, for example
Composites-Opt. A generator holds a prefix and short names. The six oldest
kinds (bool, integer, enumerated, real, octet_string, bit_string) have no
prefix: their type names are already the full names (INTEGER-0-100-FALSE).
pycrate spells a hyphen in a type name as an underscore.

Every row has, for each variant (aper, uper), the answer of each oracle: "py"
for pycrate and "er" for Erlang, as hex or, for a long answer, {sha256, octets};
null when that oracle gave no answer, with a note in "refused". When the two
answers differ, the row names the one that is expected, "expected": {variant:
"py" or "er" or "derived"}, and the clause in "decided_by". A "derived" answer is
the octets that a clause gives from another answer; the row keeps them, with
how, under "derived".

Run all generators with: PATH=~/.local/opt/otp-29.1.1/bin:$PATH
~/.local/opt/pycrate-0.8.1/bin/python testing.py

Revisions:
  - 2026-10-20 00:02: initial creation, with the helpers of the earlier generators
  - 2026-10-20 00:43: read three ASN.1 files (testing_otp.asn1 for OTP, testing_pycrate.asn1 for
    pycrate); the answers of a row are py and er for each variant (compose, expected)
"""

import atexit
import hashlib
import json
import os
import shutil
import subprocess
import sys
import tempfile

from pycrate_asn1c.asnproc import compile_text, generate_modules
from pycrate_asn1c.generator import PycrateGenerator

HERE = os.path.dirname(os.path.abspath(__file__))
ERL = os.path.join(HERE, "erlang")
ASN1 = os.path.join(HERE, "testing.asn1")
ASN1_OTP = os.path.join(HERE, "testing_otp.asn1")
ASN1_PYCRATE = os.path.join(HERE, "testing_pycrate.asn1")
MODULE = "Testing"
MODULE_OTP = "TestingOtp"
MODULE_PYCRATE = "TestingPycrate"
LIMIT = 600

_STATE = {}


def full_name(prefix, short):
    """The name of a type in testing.asn1."""
    if prefix:
        return prefix + "-" + short
    return short


class _Types:
    """The pycrate objects of the types that one prefix names."""

    def __init__(self, modules, prefix):
        self._modules = modules
        self._prefix = prefix

    def __getattr__(self, short):
        name = full_name(self._prefix, short).replace("-", "_")
        for module in self._modules:
            if hasattr(module, name):
                return getattr(module, name)
        raise AttributeError(name)


def read_text(path):
    with open(path, encoding="utf-8", newline="") as handle:
        return handle.read()


def pycrate_module(prefix):
    """Compile testing.asn1 and testing_pycrate.asn1 once and return the types of the prefix."""
    if "pycrate" not in _STATE:
        compile_text(read_text(ASN1) + "\n" + read_text(ASN1_PYCRATE))
        tmp = tempfile.mkdtemp()
        atexit.register(shutil.rmtree, tmp, True)
        generate_modules(PycrateGenerator, os.path.join(tmp, "gen_testing.py"))
        sys.path.insert(0, tmp)
        generated = __import__("gen_testing")
        _STATE["pycrate"] = [getattr(generated, MODULE), getattr(generated, MODULE_PYCRATE)]
    return _Types(_STATE["pycrate"], prefix)


def pycrate_encode(module, rows):
    """Return [(aper, uper)] hex for rows of (short type name, python value).

    A value that pycrate refuses or fails on gives ("error <exception>", the same): no answer.
    """
    out = []
    for kind, value in rows:
        try:
            obj = getattr(module, kind)
            obj.set_val(value)
            out.append((obj.to_aper().hex(), obj.to_uper().hex()))
        except Exception as exc:  # a refusal by pycrate is an answer: none
            text = "error " + type(exc).__name__
            out.append((text, text))
    return out


def _otp_build():
    """Compile testing.asn1 and testing_otp.asn1 with asn1ct for per and uper, in parallel, once."""
    keep = os.environ.get("TESTING_OTP_BUILD")
    if keep and os.path.isdir(os.path.join(keep, "uper")):
        _STATE["otp"] = {"aper": os.path.join(keep, "aper"), "uper": os.path.join(keep, "uper")}
        return
    tmp = keep or tempfile.mkdtemp()
    if not keep:
        atexit.register(shutil.rmtree, tmp, True)
    os.makedirs(tmp, exist_ok=True)
    shutil.copyfile(ASN1, os.path.join(tmp, MODULE + ".asn1"))
    shutil.copyfile(ASN1_OTP, os.path.join(tmp, MODULE_OTP + ".asn1"))
    running = []
    for variant, option in (("aper", "per"), ("uper", "uper")):
        outdir = os.path.join(tmp, variant)
        os.makedirs(outdir)
        for module in (MODULE, MODULE_OTP):
            process = subprocess.Popen(
                [
                    "erl",
                    "-noshell",
                    "-eval",
                    f'ok = asn1ct:compile("{module}", [{{outdir, "{outdir}"}}, {option}]), halt().',
                ],
                cwd=tmp,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
            running.append((variant, outdir, module, process))
    dirs = {}
    for variant, outdir, module, process in running:
        out, err = process.communicate()
        if process.returncode != 0:
            raise SystemExit(f"asn1ct {variant} {module} failed: {out.decode()} {err.decode()}")
        dirs[variant] = outdir
    _STATE["otp"] = dirs


def otp_names():
    """The type names that testing_otp.asn1 defines: OTP answers them from the module TestingOtp."""
    if "otp_names" not in _STATE:
        _STATE["otp_names"] = set()
        for line in read_text(ASN1_OTP).split("\n"):
            if "::=" in line and line[:1].isupper() and " DEFINITIONS " not in line:
                _STATE["otp_names"].add(line.split()[0])
    return _STATE["otp_names"]


def otp_raw(prefix, rows):
    """Return {"aper": [hex or error text], "uper": [...]} for rows of (short type name, Erlang term text)."""
    if "otp" not in _STATE:
        _otp_build()
    result = {"aper": [None] * len(rows), "uper": [None] * len(rows)}
    for module in (MODULE, MODULE_OTP):
        picked = [
            index
            for index, (kind, _) in enumerate(rows)
            if (full_name(prefix, kind) in otp_names()) == (module == MODULE_OTP)
        ]
        if not picked:
            continue
        lines = "".join(f"{full_name(prefix, rows[i][0])}\t{rows[i][1]}\n" for i in picked)
        for variant in ("aper", "uper"):
            done = subprocess.run(
                ["escript", os.path.join(ERL, "encode_batch.escript"), _STATE["otp"][variant], module],
                input=lines,
                check=True,
                capture_output=True,
                text=True,
            )
            for index, answer in zip(picked, done.stdout.split("\n")[: len(picked)]):
                result[variant][index] = answer
    return result


def otp_encode(prefix, rows):
    """Return [(aper, uper)] hex for rows of (short type name, Erlang term text)."""
    result = otp_raw(prefix, rows)
    return list(zip(result["aper"], result["uper"]))


def cell(hexed):
    """One answer of a row: the hex text, or {sha256, octets} when it is long."""
    if hexed is None or isinstance(hexed, dict):
        return hexed
    if len(hexed) <= LIMIT:
        return hexed
    return {"sha256": hashlib.sha256(bytes.fromhex(hexed)).hexdigest(), "octets": len(hexed) // 2}


def answered(text):
    """True for the hex text of an answer, false for None and for an "error ..." text."""
    return text is not None and not text.startswith("error")


def compose(py, er, choose=None, clause=None, derived=None, expected=None):
    """Return the answer fields of a row from the answers of the two oracles.

    py and er are (aper, uper) pairs of hex text, "error ..." text or None. The fields
    are aper and uper (each {"py", "er"}), refused (the short note of each answer that
    is missing but was asked), expected, decided_by and derived. Where both oracles
    answer and differ, expected names choose ("py" or "er"); without choose the run
    stops. expected (variant -> "py", "er" or "derived") sets a variant by hand, and
    derived is {"aper", "uper", "how"}.
    """
    row = {}
    exp = {}
    refused = {}
    for slot, variant in enumerate(("aper", "uper")):
        p = py[slot] if py is not None and answered(py[slot]) else None
        e = er[slot] if er is not None and answered(er[slot]) else None
        row[variant] = {"py": cell(p), "er": cell(e)}
        for name, pair in (("py", py), ("er", er)):
            if pair is not None and not answered(pair[slot]):
                refused[name] = str(pair[slot])[:80]
        if expected and variant in expected:
            exp[variant] = expected[variant]
        elif p is not None and e is not None and p != e:
            if choose is None:
                raise SystemExit(f"oracles disagree on {variant}: py={p[:60]} er={e[:60]}")
            exp[variant] = choose
    if refused:
        row["refused"] = refused
    if exp:
        row["expected"] = exp
    if clause:
        row["decided_by"] = clause
    if derived:
        row["derived"] = {name: (cell(value) if name != "how" else value) for name, value in derived.items()}
    return row


def merge(rows, py, er, clauses):
    """Join the answers of the oracles into JSON rows (see compose).

    rows are dicts with "type" and a "value" or an "input"; py and er are the lists from
    pycrate_encode and otp_encode. When both answer and differ, or only OTP answers (pycrate
    refuses or fails), the run stops unless clauses decides the row. clauses is a dict from
    the key of a row (the type and the text of the value, 40 characters) to (oracle, clause
    text), or a function from the row to that pair or None. An OTP answer that is missing
    leaves the answer of pycrate alone.
    """
    out = []
    for row, p, e in zip(rows, py, er):
        item = dict(row)
        p_ok = answered(p[0]) and answered(p[1])
        e_ok = answered(e[0]) and answered(e[1])
        differ = p_ok and e_ok and p != e
        if differ or (e_ok and not p_ok):
            shown = row.get("value", row.get("input", row.get("count")))
            key = f'{row["type"]} {str(shown)[:40]}'
            decision = clauses(row) if callable(clauses) else clauses.get(key)
            if decision is None:
                raise SystemExit(f"oracles disagree on {key}: py={(p[0][:80], p[1][:80])} er={(e[0][:80], e[1][:80])}")
            choice, text = decision
            item.update(compose(p, e, choose="py" if choice == "pycrate" else "er", clause=text))
        elif not p_ok and not e_ok:
            raise SystemExit(f"no oracle answers {row}: py={p} er={e}")
        else:
            item.update(compose(p, e))
        out.append(item)
    return out


def expected(row, variant):
    """The expected answer of a row in a variant: hex text or {sha256, octets}, None for none."""
    name = row.get("expected", {}).get(variant)
    if name == "derived":
        return row["derived"][variant]
    answers = row[variant]
    if name:
        return answers[name]
    return answers["py"] if answers["py"] is not None else answers["er"]


def write(document):
    """Write testing.json: one key for each kind, each holding that kind's vectors."""
    with open(os.path.join(HERE, "testing.json"), "w", encoding="utf-8") as handle:
        json.dump(document, handle, indent=2, ensure_ascii=False)
        handle.write("\n")
