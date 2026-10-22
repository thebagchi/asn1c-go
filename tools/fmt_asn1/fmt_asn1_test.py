"""Tests for fmt_asn1.py: one test for each finding of review.md, and two properties.

Run with:
    python3 -I -m unittest discover -s tools/fmt_asn1 -p '*_test.py' -v
"""

import bisect
import inspect
import os
import stat
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

import fmt_asn1  # noqa: E402  (the path above makes this import work under python -I)

SCRIPT = os.path.join(HERE, "fmt_asn1.py")

EXIT_CHANGED = 1
EXIT_FAILED = 2

HEADER = "M DEFINITIONS ::= BEGIN\n"
FOOTER = "END\n"

# The example of finding F3.
F3_INPUT = (
    "M DEFINITIONS ::= BEGIN\n"
    "Weekday ::= INTEGER {\n"
    "                monday(1)\n"
    "            }\n"
    "id-x Type\n"
    "    ::= 1\n"
    "LongerName ::= BOOLEAN\n"
    "END\n"
)

# The example of finding F4.
F4_INPUT = (
    "M DEFINITIONS ::= BEGIN\n"
    "A ::= INTEGER {\n"
    "          x(1)\n"
    "}\n"
    "LongerName ::= BOOLEAN\n"
    "END\n"
)

# Small modules for the two properties.
SAMPLES = [
    F3_INPUT,
    F4_INPUT,
    HEADER + "T ::= UTF8String\nv T ::= <T>a\tb   </T>\n" + FOOTER,
    HEADER + "v T ::= <T>it's</T>\nLongName ::= INTEGER\nB ::= BOOLEAN\n" + FOOTER,
    HEADER + 'v T ::= <T>say "hi" -- not a comment</T>\nL ::= "a\tb"   \nX ::= 1\n' + FOOTER,
    HEADER + "A\t::=\tINTEGER   -- c\t\n\tB ::= BOOLEAN  \r\nLongest ::= NULL\r\n" + FOOTER,
    HEADER + 'v T ::= "a\rb"\nw T ::= <a><b/>\t</a>\n' + FOOTER,
    HEADER + "S ::= SEQUENCE {\n\ta INTEGER,\n\tb BOOLEAN\n}\nLongerName ::= NULL\n" + FOOTER,
    "",
    "\n\n",
]


def run_script(
    *arguments: str,
    env: dict[str, str] | None = None,
) -> subprocess.CompletedProcess[bytes]:
    """Run fmt_asn1.py in a subprocess, without -I so that PYTHONIOENCODING counts."""
    return subprocess.run(
        [sys.executable, SCRIPT, *arguments],
        capture_output=True,
        env=env,
        check=False,
    )


def without_spacing(text: str) -> str:
    """The text with all white space removed, outside strings and XML text."""
    scan = fmt_asn1.Scan(text)

    return "".join(
        char
        for index, char in enumerate(text)
        if not (char.isspace() and scan.states[index] not in fmt_asn1.STRINGS)
    )


class RegressionTest(unittest.TestCase):
    def test_regression_f1_xml_tab(self) -> None:
        text = HEADER + "T ::= UTF8String\nv T ::= <T>a\tb   </T>\n" + FOOTER

        self.assertIn("<T>a\tb   </T>", fmt_asn1.formatted(text))

    def test_regression_f1_xml_apostrophe(self) -> None:
        text = HEADER + "v T ::= <T>it's</T>\nLongName ::= INTEGER\nB ::= BOOLEAN\n" + FOOTER
        want = (
            HEADER
            + "v T      ::= <T>it's</T>\n"
            + "LongName ::= INTEGER\n"
            + "B        ::= BOOLEAN\n"
            + FOOTER
        )

        self.assertEqual(fmt_asn1.formatted(text), want)

    def test_regression_f1_xml_quote_and_dashes(self) -> None:
        text = (
            HEADER
            + 'v T ::= <T>say "hi" -- not a comment</T>\n'
            + 'LongName ::= "a\tb"\n'
            + FOOTER
        )
        want = (
            HEADER
            + 'v T      ::= <T>say "hi" -- not a comment</T>\n'
            + 'LongName ::= "a\tb"\n'
            + FOOTER
        )

        self.assertEqual(fmt_asn1.formatted(text), want)

    def test_regression_f1_xml_nested_and_empty(self) -> None:
        text = (
            HEADER
            + "v T ::= <a><b/>\t <c>x</c></a>\n"
            + "w T ::= <e/>\n"
            + "LongName ::= NULL\n"
            + FOOTER
        )
        result = fmt_asn1.formatted(text)

        self.assertIn("<a><b/>\t <c>x</c></a>", result)
        self.assertIn("w T      ::= <e/>\n", result)

    def test_regression_f2_lone_cr(self) -> None:
        text = HEADER + 'v T ::= "a\rb"\n' + FOOTER

        self.assertIn('"a\rb"', fmt_asn1.formatted(text))

    def test_regression_f2_crlf_line_end(self) -> None:
        text = HEADER.replace("\n", "\r\n") + "A ::= INTEGER\r\n" + FOOTER.replace("\n", "\r\n")
        result = fmt_asn1.formatted(text)

        self.assertNotEqual(result, text)
        self.assertNotIn("\r", result)

    def test_regression_f2_crlf_inside_string(self) -> None:
        text = HEADER + 'v T ::= "a\r\nb"\n' + FOOTER

        self.assertIn('"a\r\nb"', fmt_asn1.formatted(text))

    def test_regression_f2_crlf_file_is_listed_and_rewritten(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = os.path.join(directory, "crlf.asn1")
            with open(path, "wb") as handle:
                handle.write(b"M DEFINITIONS ::= BEGIN\r\nA ::= INTEGER\r\nEND\r\n")

            listed = run_script("-l", path)
            self.assertEqual(listed.returncode, EXIT_CHANGED)

            run_script("-w", path)
            with open(path, "rb") as handle:
                self.assertNotIn(b"\r", handle.read())

    def test_regression_f2_lone_cr_file_is_kept(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = os.path.join(directory, "cr.asn1")
            source = b'M DEFINITIONS ::= BEGIN\nv T ::= "a\rb"\nA\t::= NULL\nEND\n'
            with open(path, "wb") as handle:
                handle.write(source)

            run_script("-w", path)
            with open(path, "rb") as handle:
                self.assertEqual(
                    handle.read(),
                    b'M DEFINITIONS ::= BEGIN\nv T ::= "a\rb"\nA   ::= NULL\nEND\n',
                )

    def test_regression_f3_continuation_range(self) -> None:
        want = (
            "M DEFINITIONS ::= BEGIN\n"
            "Weekday    ::= INTEGER {\n"
            "                   monday(1)\n"
            "               }\n"
            "id-x Type\n"
            "    ::= 1\n"
            "LongerName ::= BOOLEAN\n"
            "END\n"
        )

        self.assertEqual(fmt_asn1.formatted(F3_INPUT), want)

    def test_regression_f4_margin_lines(self) -> None:
        want = (
            "M DEFINITIONS ::= BEGIN\n"
            "A          ::= INTEGER {\n"
            "                   x(1)\n"
            "}\n"
            "LongerName ::= BOOLEAN\n"
            "END\n"
        )

        self.assertEqual(fmt_asn1.formatted(F4_INPUT), want)

    def test_regression_f5_write_keeps_symlink_and_mode(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            target = os.path.join(directory, "d.asn1")
            link = os.path.join(directory, "dl.asn1")
            partial = target + fmt_asn1.PARTIAL
            with open(target, "w", encoding="utf-8") as handle:
                handle.write("M DEFINITIONS ::= BEGIN\nA ::= INTEGER\nLonger ::= NULL\nEND\n")
            with open(partial, "w", encoding="utf-8") as handle:
                handle.write("keep")
            os.chmod(target, 0o600)
            os.symlink(target, link)

            result = run_script("-w", link)

            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertTrue(os.path.islink(link))
            self.assertEqual(stat.S_IMODE(os.stat(target).st_mode), 0o600)
            with open(target, encoding="utf-8") as handle:
                self.assertIn("A      ::= INTEGER", handle.read())
            with open(partial, encoding="utf-8") as handle:
                self.assertEqual(handle.read(), "keep")
            self.assertEqual(
                sorted(os.listdir(directory)),
                ["d.asn1", "d.asn1.partial", "dl.asn1"],
            )

    def test_regression_f6_print_with_strict_stdout(self) -> None:
        env = dict(os.environ, PYTHONIOENCODING="utf-8:strict")
        with tempfile.TemporaryDirectory() as directory:
            path = os.path.join(directory, "c.asn1")
            source = b"M DEFINITIONS ::= BEGIN\n-- caf\xe9\nA ::= INTEGER\nEND\n"
            with open(path, "wb") as handle:
                handle.write(source)

            result = run_script(path, env=env)

            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(result.stdout, source)

    def test_regression_f7_empty_file(self) -> None:
        self.assertEqual(fmt_asn1.formatted(""), "")

        with tempfile.TemporaryDirectory() as directory:
            path = os.path.join(directory, "empty.asn1")
            open(path, "wb").close()

            self.assertEqual(run_script("-l", path).returncode, 0)

    def test_regression_f7_last_line_of_spaces(self) -> None:
        self.assertEqual(fmt_asn1.formatted(HEADER + FOOTER + "   "), HEADER + FOOTER)

    def test_regression_f7_last_line_in_open_string_keeps_spaces(self) -> None:
        result = fmt_asn1.spaced(HEADER + 'v T ::= "ab   ')

        self.assertIn('"ab   ', result)

    def test_regression_f8_missing_file(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            missing = os.path.join(directory, "nope.asn1")
            good = os.path.join(directory, "good.asn1")
            with open(good, "w", encoding="utf-8") as handle:
                handle.write("M DEFINITIONS ::= BEGIN\nA ::= INTEGER\nLonger ::= NULL\nEND\n")

            result = run_script("-l", missing, good)

            self.assertEqual(result.returncode, EXIT_FAILED)
            self.assertEqual(result.stdout.decode(), good + "\n")
            self.assertTrue(
                result.stderr.decode().startswith("fmt_asn1: error: " + missing + ": "),
                result.stderr,
            )
            self.assertNotIn(b"Traceback", result.stderr)

    def test_regression_f8_only_failure_exits_two(self) -> None:
        result = run_script("/nonexistent/nope.asn1")

        self.assertEqual(result.returncode, EXIT_FAILED)

    def test_regression_f9_every_function_is_annotated(self) -> None:
        missing: list[str] = []
        functions = [
            (name, each)
            for name, each in vars(fmt_asn1).items()
            if inspect.isfunction(each) and each.__module__ == fmt_asn1.__name__
        ]
        for name, each in functions:
            missing += _unannotated(name, each)
        for name, cls in vars(fmt_asn1).items():
            if inspect.isclass(cls) and cls.__module__ == fmt_asn1.__name__:
                for method_name, method in vars(cls).items():
                    if inspect.isfunction(method) and method.__module__ == fmt_asn1.__name__:
                        missing += _unannotated(name + "." + method_name, method)

        self.assertEqual(missing, [])

    def test_regression_f10_one_scan_of_the_spaced_text(self) -> None:
        with mock.patch.object(fmt_asn1, "Scan", side_effect=fmt_asn1.Scan) as scan:
            fmt_asn1.formatted(F3_INPUT)

        # One scan to space the text, one to format the spaced text.
        self.assertEqual(scan.call_count, 2)

    def test_regression_f11_every_character_has_a_depth(self) -> None:
        text = HEADER + "Foo ::= SEQUENCE { a INTEGER (1..2), b Bar } -- c { d\nX ::= Y\n" + FOOTER
        scan = fmt_asn1.Scan(text)
        depth = 0

        for index, char in enumerate(text):
            self.assertEqual(scan.depths[index], depth, "index %d" % index)
            if scan.states[index] == fmt_asn1.State.CODE:
                if char in fmt_asn1.OPENERS:
                    depth += 1
                elif char in fmt_asn1.CLOSERS:
                    depth = max(0, depth - 1)

    def test_regression_f12_line_of_is_bisect(self) -> None:
        text = "a\n\nbc\ndef\n"
        scan = fmt_asn1.Scan(text)
        starts = [0, 2, 3, 6, 10]

        for index in range(len(text)):
            self.assertEqual(scan.line_of(index), bisect.bisect_right(starts, index) - 1)

    def test_regression_f13_docstring_matches_behaviour(self) -> None:
        doc = fmt_asn1.__doc__ or ""

        self.assertIn("XML", doc)
        self.assertNotIn("Deciding once for the whole assignment", doc)
        self.assertNotIn("a carriage return with it", doc)


def _unannotated(name: str, function: object) -> list[str]:
    """The names of the parameters and the result of a function that have no annotation."""
    missing: list[str] = []
    signature = inspect.signature(function)  # type: ignore[arg-type]

    for parameter in signature.parameters.values():
        if parameter.name != "self" and parameter.annotation is inspect.Parameter.empty:
            missing.append(name + ":" + parameter.name)
    if signature.return_annotation is inspect.Signature.empty:
        missing.append(name + ":return")

    return missing


class ForkTest(unittest.TestCase):
    """Variant (c) of the open fork: one ::= column for each block, and a long name stays out."""

    def test_fork_c_block_column(self) -> None:
        text = (
            HEADER
            + "A ::= INTEGER\nBb ::= NULL\n\n"
            + "LongerName ::= BOOLEAN\nC ::= NULL\n"
            + FOOTER
        )
        want = (
            HEADER
            + "A  ::= INTEGER\nBb ::= NULL\n\n"
            + "LongerName ::= BOOLEAN\nC          ::= NULL\n"
            + FOOTER
        )

        self.assertEqual(fmt_asn1.formatted(text), want)

    def test_fork_c_comment_line_starts_a_block(self) -> None:
        text = (
            HEADER
            + "A ::= INTEGER\n-- note\nLongerName ::= BOOLEAN\n/* x */\nB ::= NULL\n"
            + FOOTER
        )

        self.assertEqual(fmt_asn1.formatted(text), text)

    def test_fork_c_continuation_does_not_start_a_block(self) -> None:
        text = (
            HEADER
            + "S ::= SEQUENCE {\n    a INTEGER\n}\n"
            + "LongerName ::= BOOLEAN\n"
            + FOOTER
        )
        want = (
            HEADER
            + "S          ::= SEQUENCE {\n    a INTEGER\n}\n"
            + "LongerName ::= BOOLEAN\n"
            + FOOTER
        )

        self.assertEqual(fmt_asn1.formatted(text), want)

    def test_fork_c_limit(self) -> None:
        long = "L" * (fmt_asn1.LEFT_LIMIT + 5)
        text = HEADER + "A ::= INTEGER\nBbb ::= NULL\n" + long + " ::= BOOLEAN\n" + FOOTER
        want = HEADER + "A   ::= INTEGER\nBbb ::= NULL\n" + long + " ::= BOOLEAN\n" + FOOTER

        self.assertEqual(fmt_asn1.formatted(text), want)

    def test_fork_c_name_at_the_limit_counts(self) -> None:
        name = "N" * fmt_asn1.LEFT_LIMIT
        text = HEADER + "A ::= INTEGER\n" + name + " ::= NULL\n" + FOOTER
        padding = " " * fmt_asn1.LEFT_LIMIT
        want = HEADER + "A" + padding + "::= INTEGER\n" + name + " ::= NULL\n" + FOOTER

        self.assertEqual(fmt_asn1.formatted(text), want)

    def test_fork_c_block_without_a_short_name(self) -> None:
        long = "L" * (fmt_asn1.LEFT_LIMIT + 1)
        other = "M" * (fmt_asn1.LEFT_LIMIT + 9)
        text = HEADER + long + "   ::= INTEGER\n" + other + "\t::= NULL\n" + FOOTER
        want = HEADER + long + " ::= INTEGER\n" + other + " ::= NULL\n" + FOOTER

        self.assertEqual(fmt_asn1.formatted(text), want)

    def test_fork_c_new_module_block(self) -> None:
        text = (
            "M DEFINITIONS ::= BEGIN\nA ::= INTEGER\nEND\n"
            + "N DEFINITIONS ::= BEGIN\nLongerName ::= BOOLEAN\nEND\n"
        )

        self.assertEqual(fmt_asn1.formatted(text), text)


class PropertyTest(unittest.TestCase):
    def test_idempotent(self) -> None:
        for text in SAMPLES:
            once = fmt_asn1.formatted(text)
            self.assertEqual(fmt_asn1.formatted(once), once, repr(text))

    def test_only_white_space_changes(self) -> None:
        for text in SAMPLES:
            once = fmt_asn1.formatted(text)
            # A CRLF is a line end, so it is white space that goes. Its string content stays.
            self.assertEqual(without_spacing(once), without_spacing(text), repr(text))


if __name__ == "__main__":
    unittest.main()
