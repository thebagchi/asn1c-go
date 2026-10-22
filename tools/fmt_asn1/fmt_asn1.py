#!/usr/bin/env python3
"""Format ASN.1 modules so that the ::= of the assignments in a block stands in one column.

A module gathered from several sources keeps each source's spacing, and its ::= then wanders
from line to line: one source pads its names to a column, another puts one space after each, a
third a tab. This sets the ::= of every assignment of a block one space after the block's
longest left-hand side, so that the names read down one column and the definitions down another.

A block is a run of assignments of one module. A blank line, or a line of only a comment,
between two assignments starts a new block, and so does a new module. A line that continues an
assignment, such as a SEQUENCE's components or its closing brace, does not. A left-hand side
longer than LEFT_LIMIT columns does not count towards its block's column and gets exactly one
space before its ::=, so that one long name does not move the rest of its block.

Only white space outside strings and XML text changes, so a module means what it meant before:

  - a tab outside a string or XML text becomes the spaces that reach the same column, a tab
    every eight;
  - white space at the end of a line goes, unless the line ends inside a string or XML text;
  - a line ends at a line feed or at a carriage return and a line feed, and the carriage return
    of the pair goes with the white space at the end of the line, except inside a string or XML
    text; a carriage return alone is an ordinary character, and a file is read and written
    without any translation of line ends;
  - the ::= of each assignment moves to its block's column, with exactly one space after it;
  - white space within an assignment's left-hand side becomes one space: a column a source lined
    up there - a value's type, with tabs - is the ::='s to line up now.

XML value notation, as in "v T ::= <T>a b</T>", is text and not code: it starts at a < that is
the first item after a ::= outside every bracket, and it ends with the element that the < opens.
Inside it a quotation mark, an apostrophe, a pair of hyphens and white space are ordinary
characters of the value.

A line that continues an assignment moves with its ::= when the assignment was laid out from its
definition - its first continuing line indented as far as the text after the ::= or further, as

    Weekday ::= INTEGER {
                    monday(1), tuesday(2)
                } (1..7)

is. Then each continuing line indented that far moves, and a line left of that column, such as a
closing brace at the margin, stays where it is, as the components of a SEQUENCE usually do when
the assignment was laid out from the margin. An assignment is over, and its lines stop moving,
at the first line that starts with a name outside every bracket at or left of the indent of the
assignment's left-hand side.

An assignment is a line that starts with a name, inside a module's body and outside any bracket,
and holds a ::= outside any bracket. A module header's ::= is not one, nor is anything between a
MACRO's BEGIN and its END. Comments and strings are skipped wherever they are, so a ::= in either
is left alone.

Usage:
    python3 tools/fmt_asn1/fmt_asn1.py FILE...       # print each file formatted
    python3 tools/fmt_asn1/fmt_asn1.py -w FILE...    # rewrite each file in place
    python3 tools/fmt_asn1/fmt_asn1.py -l FILE...    # list each file that would change

With -l the exit status is 1 when a file would change, so that it serves as a check. A file that
cannot be read or written gets one line on stderr, "fmt_asn1: error: FILE: what failed: why",
the other files are still done, and the exit status is 2.
"""

import argparse
import bisect
import contextlib
import enum
import os
import stat
import sys
import tempfile


class State(enum.IntEnum):
    """What a character of the text is part of."""

    CODE = 0
    LINE_COMMENT = 1
    BLOCK_COMMENT = 2
    CSTRING = 3
    QUOTED = 4
    XML = 5


# The states whose text is a comment.
COMMENTS = (State.LINE_COMMENT, State.BLOCK_COMMENT)

# The states whose text is a value, where a tab is a character and not a spacing.
STRINGS = (State.CSTRING, State.QUOTED, State.XML)

# One step of the scan: the state, the bracket depth and the nesting after it, and the next index.
Step = tuple[State, int, int, int]

# The lexical items the scan tells apart.
ASSIGNMENT = "::="
LINE_MARK = "--"
BLOCK_OPEN = "/*"
BLOCK_CLOSE = "*/"
CSTRING_MARK = '"'
CSTRING_ESCAPE = '""'
QUOTE_MARK = "'"
OPENERS = "{(["
CLOSERS = "})]"
HYPHEN = "-"
NEWLINE = "\n"
SPACE = " "
TAB = "\t"

# The markup of XML value notation. A tag may hold quoted attribute values, with a > in them.
XML_OPEN = "<"
XML_TAG_CLOSE = ">"
XML_END_OPEN = "</"
XML_EMPTY_CLOSE = "/>"
XML_ATTRIBUTE_QUOTES = "\"'"
XML_SECTIONS = (
    ("<!--", "-->"),
    ("<![CDATA[", "]]>"),
    ("<?", "?>"),
)

# The reserved words that open and close a module's body, and the one that makes a BEGIN a
# macro's instead.
BEGIN = "BEGIN"
END = "END"
MACRO = "MACRO"

# What a BEGIN opened.
MODULE_BODY, MACRO_BODY = "module", "macro"

# A left-hand side longer than this many columns does not count towards the column of its block.
LEFT_LIMIT = 40

# A tab reaches the next multiple of this many columns, as a terminal shows it.
TAB_WIDTH = 8

# How a file is read and written: as UTF-8, with any byte that is not passed through as it was -
# some modules are Latin-1, in comments and strings this leaves alone - and with no translation
# of line ends. A file is rewritten by writing a new file beside it, under a name that ends in
# PARTIAL, and renaming that over it, so that a write cut short leaves the module as it was.
ENCODING = "utf-8"
UNDECODED = "surrogateescape"
PARTIAL = ".partial"
READ_MODE = "r"
WRITE_MODE = "w"
NO_TRANSLATION = ""

# The program name in an error line, and the exit statuses.
PROGRAM = "fmt_asn1"
EXIT_CHANGED = 1
EXIT_FAILED = 2

# What failed, in an error line.
CANNOT_READ = "cannot read"
CANNOT_WRITE = "cannot write"


class Scan:
    """What a text holds, character by character: each one's state and bracket depth; the ::=
    outside every bracket, and the words outside every bracket, as (index, token) in order; and
    the index each line starts at."""

    def __init__(self, text: str) -> None:
        self.text = text
        self.states: list[State] = [State.CODE] * len(text)
        self.depths: list[int] = [0] * len(text)
        self.events: list[tuple[int, str]] = []
        self.starts = _line_starts(text)
        self._expecting = False
        self._scanned()

    def line_of(self, index: int) -> int:
        """The line an index of the text is on."""
        return bisect.bisect_right(self.starts, index) - 1

    def _scanned(self) -> None:
        text, state, depth, nesting, index = self.text, State.CODE, 0, 0, 0

        while index < len(text):
            start, before = index, depth

            if state == State.CODE:
                state, depth, nesting, index = self._code(index, depth)
            elif state == State.LINE_COMMENT:
                state, index = self._line_comment(index)
            elif state == State.BLOCK_COMMENT:
                state, nesting, index = self._block_comment(index, nesting)
            elif state == State.CSTRING:
                state, index = self._cstring(index)
            elif state == State.QUOTED:
                state, index = self._quoted(index)
            else:
                state, nesting, index = self._xml(index, nesting)

            if before:
                stop = min(index, len(text))
                self.depths[start:stop] = [before] * (stop - start)

    def _marked(self, index: int, count: int, state: State) -> int:
        """Give count characters from index one state, and return the index after them."""
        for at in range(index, min(index + count, len(self.text))):
            self.states[at] = state

        return index + count

    def _code(self, index: int, depth: int) -> Step:
        """One step of code: a comment or a string opening, a bracket, a ::= or a word outside
        every bracket, or any other character. XML text opens at the first item after a ::=
        outside every bracket, when that item is a <; the step that opens it stays on the <."""
        text = self.text
        char = text[index]

        if char == LINE_MARK[0] and text.startswith(LINE_MARK, index):
            after = self._marked(index, len(LINE_MARK), State.LINE_COMMENT)

            return State.LINE_COMMENT, depth, 0, after

        if char == BLOCK_OPEN[0] and text.startswith(BLOCK_OPEN, index):
            after = self._marked(index, len(BLOCK_OPEN), State.BLOCK_COMMENT)

            return State.BLOCK_COMMENT, depth, 1, after

        if char.isspace():
            return State.CODE, depth, 0, index + 1

        expecting, self._expecting = self._expecting, False

        if expecting and char == XML_OPEN:
            return State.XML, depth, 0, index

        if char == CSTRING_MARK:
            return State.CSTRING, depth, 0, self._marked(index, 1, State.CSTRING)

        if char == QUOTE_MARK:
            return State.QUOTED, depth, 0, self._marked(index, 1, State.QUOTED)

        if char in OPENERS:
            return State.CODE, depth + 1, 0, index + 1

        if char in CLOSERS:
            return State.CODE, max(0, depth - 1), 0, index + 1

        if depth == 0 and char == ASSIGNMENT[0] and text.startswith(ASSIGNMENT, index):
            self.events.append((index, ASSIGNMENT))
            self._expecting = True

            return State.CODE, depth, 0, index + len(ASSIGNMENT)

        if depth == 0 and char.isalpha() and not _worded(text, index - 1):
            end = _word_end(text, index)
            self.events.append((index, text[index:end]))

            return State.CODE, depth, 0, end

        return State.CODE, depth, 0, index + 1

    def _line_comment(self, index: int) -> tuple[State, int]:
        """One step of a comment that runs to the next -- or to the end of its line."""
        if self.text[index] == NEWLINE:
            return State.CODE, index + 1

        if self.text.startswith(LINE_MARK, index):
            return State.CODE, self._marked(index, len(LINE_MARK), State.LINE_COMMENT)

        return State.LINE_COMMENT, self._marked(index, 1, State.LINE_COMMENT)

    def _block_comment(self, index: int, nesting: int) -> tuple[State, int, int]:
        """One step of a /* */ comment, which X.680 lets nest."""
        if self.text.startswith(BLOCK_OPEN, index):
            after = self._marked(index, len(BLOCK_OPEN), State.BLOCK_COMMENT)

            return State.BLOCK_COMMENT, nesting + 1, after

        if self.text.startswith(BLOCK_CLOSE, index):
            after = self._marked(index, len(BLOCK_CLOSE), State.BLOCK_COMMENT)
            if nesting == 1:
                return State.CODE, 0, after

            return State.BLOCK_COMMENT, nesting - 1, after

        return State.BLOCK_COMMENT, nesting, self._marked(index, 1, State.BLOCK_COMMENT)

    def _cstring(self, index: int) -> tuple[State, int]:
        """One step of a cstring, where a doubled quotation mark is one character of it."""
        if self.text.startswith(CSTRING_ESCAPE, index):
            return State.CSTRING, self._marked(index, len(CSTRING_ESCAPE), State.CSTRING)

        if self.text[index] == CSTRING_MARK:
            return State.CODE, self._marked(index, 1, State.CSTRING)

        return State.CSTRING, self._marked(index, 1, State.CSTRING)

    def _quoted(self, index: int) -> tuple[State, int]:
        """One step of a bstring or an hstring, which ends at its closing apostrophe."""
        if self.text[index] == QUOTE_MARK:
            return State.CODE, self._marked(index, 1, State.QUOTED)

        return State.QUOTED, self._marked(index, 1, State.QUOTED)

    def _xml(self, index: int, nesting: int) -> tuple[State, int, int]:
        """One step of XML text: a piece of markup, or one character of text. The nesting counts
        the elements that are open, and the text ends when the last one closes."""
        if self.text[index] != XML_OPEN:
            return State.XML, nesting, self._marked(index, 1, State.XML)

        end = _markup_end(self.text, index)
        after = self._marked(index, end - index, State.XML)
        nesting = max(0, nesting + _element_change(self.text[index:end]))

        if nesting == 0:
            return State.CODE, 0, after

        return State.XML, nesting, after


def _markup_end(text: str, index: int) -> int:
    """Where the markup that starts at index ends: a comment, a CDATA section or an instruction
    at its closer, or a tag at its > outside the quotes of its attribute values."""
    for opener, closer in XML_SECTIONS:
        if text.startswith(opener, index):
            found = text.find(closer, index + len(opener))

            return len(text) if found < 0 else found + len(closer)

    quote = ""

    for at in range(index + len(XML_OPEN), len(text)):
        char = text[at]
        if quote:
            quote = "" if char == quote else quote
        elif char in XML_ATTRIBUTE_QUOTES:
            quote = char
        elif char == XML_TAG_CLOSE:
            return at + 1

    return len(text)


def _element_change(markup: str) -> int:
    """How many elements one piece of markup opens: 1 for a start tag, -1 for an end tag, and 0
    for an empty element, a comment, a CDATA section or an instruction."""
    if markup.startswith(XML_END_OPEN):
        return -1

    section = any(markup.startswith(opener) for opener, _ in XML_SECTIONS)
    if markup.endswith(XML_EMPTY_CLOSE) or section:
        return 0

    return 1


def _worded(text: str, index: int) -> bool:
    """Whether the character at index can be part of a word, so that a letter after it does not
    start one."""
    return index >= 0 and (text[index].isalnum() or text[index] == HYPHEN)


def _word_end(text: str, index: int) -> int:
    """Where the word that starts at index ends: letters, digits and single hyphens, a hyphen
    never last, and never two together, which start a comment."""
    end = index + 1

    while end < len(text):
        char = text[end]
        joined = char == HYPHEN and end + 1 < len(text) and text[end + 1].isalnum()
        if not char.isalnum() and not joined:
            break

        end += 1

    return end


def spaced(text: str) -> str:
    """The text with a tab outside a string turned into spaces, and the white space at the end of
    a line removed where the line does not end inside a string. A last line of white space goes,
    and a text with no line left is empty."""
    scan = Scan(text)
    lines: list[str] = []
    line: list[str] = []
    column = 0

    for index, char in enumerate(text):
        if char == NEWLINE:
            lines.append(_ended("".join(line), scan.states[index]))
            line, column = [], 0
            continue

        if char == TAB and scan.states[index] not in STRINGS:
            width = TAB_WIDTH - column % TAB_WIDTH
            line.append(SPACE * width)
            column += width
            continue

        line.append(char)
        column += 1

    last = _ended("".join(line), scan.states[-1]) if line else ""
    if last:
        lines.append(last)

    if not lines:
        return ""

    return NEWLINE.join(lines) + NEWLINE


def _ended(line: str, state: State) -> str:
    """A line without the white space at its end, unless it ends inside a string."""
    if state in STRINGS:
        return line

    return line.rstrip()


class Assignment:
    """One assignment line: where it is, its module, the column of its ::=, and its left-hand
    side as it will be set."""

    def __init__(self, line: int, module: int, column: int) -> None:
        self.line = line
        self.module = module
        self.column = column
        self.left = ""


def assignments(scan: Scan) -> tuple[list[Assignment], dict[int, int]]:
    """Every assignment line of the scanned text, and where each module's body ends: the line of
    its END, by module."""
    found: list[Assignment] = []
    ends: dict[int, int] = {}
    seen: set[int] = set()
    stack: list[str] = []
    modules, macro = 0, False

    for index, token in scan.events:
        if token == ASSIGNMENT:
            line = scan.line_of(index)
            inside = stack == [MODULE_BODY]
            if inside and line not in seen and _opens(scan, scan.starts[line], index):
                seen.add(line)
                found.append(Assignment(line, modules, index - scan.starts[line]))

            continue

        if token == BEGIN:
            if macro:
                stack.append(MACRO_BODY)
            else:
                stack.append(MODULE_BODY)
                modules += 1
        elif token == END and stack:
            if stack.pop() == MODULE_BODY:
                ends[modules] = scan.line_of(index)

        macro = token == MACRO

    return found, ends


def _line_starts(text: str) -> list[int]:
    """The index each line of the text starts at."""
    starts = [0]

    for index, char in enumerate(text):
        if char == NEWLINE:
            starts.append(index + 1)

    return starts


def _opens(scan: Scan, start: int, mark: int) -> bool:
    """Whether the line starting at start opens an assignment: its first character, before the
    ::= at mark, is a letter in code outside every bracket."""
    first = start

    while first < mark and scan.text[first] == SPACE:
        first += 1

    if first == mark:
        return False

    return _starts_word(scan, first)


def _starts_word(scan: Scan, index: int) -> bool:
    """Whether the character at index is a letter in code outside every bracket."""
    return (
        scan.states[index] == State.CODE
        and scan.depths[index] == 0
        and scan.text[index].isalpha()
    )


class Page:
    """The spaced text being laid out: its scan, its lines as they were, and its lines as they
    become."""

    def __init__(self, text: str) -> None:
        self.scan = Scan(text)
        self.source = text.split(NEWLINE)
        self.lines = list(self.source)


def formatted(text: str) -> str:
    """The text with tabs spaced and the ::= of each block of assignments in one column."""
    page = Page(spaced(text))
    found, ends = assignments(page.scan)

    for each in found:
        start = page.scan.starts[each.line]
        each.left = _left(page.source[each.line], each.column, page.scan, start)

    blocks = _blocks(page, found)
    columns: dict[int, int] = {}
    for block, each in zip(blocks, found):
        if len(each.left) <= LEFT_LIMIT:
            columns[block] = max(columns.get(block, 0), len(each.left) + 1)

    for at, each in enumerate(found):
        limit = _limit(found, at, ends, len(page.source))
        column = max(columns.get(blocks[at], 0), len(each.left) + 1)
        _aligned(page, each, column, _stop(page, each, limit))

    return NEWLINE.join(page.lines)


def _blocks(page: Page, found: list[Assignment]) -> list[int]:
    """The block of each assignment: a run of assignments of one module, with no blank line and
    no line of only a comment between two of them. The lines that continue an assignment do not
    end a block."""
    blocks: list[int] = []
    block = 0

    for at, each in enumerate(found):
        if at:
            before = found[at - 1]
            gap = range(before.line + 1, each.line)
            if each.module != before.module or any(_separates(page, index) for index in gap):
                block += 1

        blocks.append(block)

    return blocks


def _separates(page: Page, index: int) -> bool:
    """Whether a line is blank, or holds only a comment."""
    line = page.source[index]
    first = len(line) - len(line.lstrip())

    if first == len(line):
        return True

    return page.scan.states[page.scan.starts[index] + first] in COMMENTS


def _limit(found: list[Assignment], at: int, ends: dict[int, int], count: int) -> int:
    """The line where the room of one assignment ends: the next assignment of its module, or the
    END of its module, or the end of the text."""
    each = found[at]

    if at + 1 < len(found) and found[at + 1].module == each.module:
        return found[at + 1].line

    return ends.get(each.module, count)


def _stop(page: Page, each: Assignment, limit: int) -> int:
    """The line where an assignment ends: the first line before limit that starts with a name in
    code outside every bracket, at or left of the indent of the assignment's left-hand side."""
    margin = _indent(page.source[each.line])

    for index in range(each.line + 1, limit):
        line = page.source[index]
        indent = _indent(line)
        first = page.scan.starts[index] + indent
        if indent <= margin and indent < len(line) and _starts_word(page.scan, first):
            return index

    return limit


def _aligned(page: Page, each: Assignment, column: int, stop: int) -> None:
    """Move one assignment's ::= to column, and the lines up to stop that continue it with it
    when it was laid out from its definition. A line left of the old start of the definition
    stays."""
    line = page.source[each.line]
    right = line[each.column + len(ASSIGNMENT):]
    definition = right.lstrip()

    moved = each.left + SPACE * (column - len(each.left)) + ASSIGNMENT
    if definition:
        moved += SPACE + definition

    page.lines[each.line] = moved

    if not definition:
        return

    before = each.column + len(ASSIGNMENT) + len(right) - len(definition)
    after = column + len(ASSIGNMENT) + len(SPACE)
    shift = after - before
    continuing = [index for index in range(each.line + 1, stop) if _continues(page, index)]

    if shift == 0 or not continuing or _indent(page.source[continuing[0]]) < before:
        return

    for index in continuing:
        if _indent(page.source[index]) >= before:
            page.lines[index] = _shifted(page.source[index], shift)


def _left(line: str, column: int, scan: Scan, start: int) -> str:
    """An assignment's left-hand side as it is set: its indent kept, each run of spaces in code
    after it made one, and none at its end."""
    indent = _indent(line)
    kept, spacing = [line[:indent]], False

    for offset in range(indent, column):
        char = line[offset]
        if char == SPACE and scan.states[start + offset] == State.CODE:
            spacing = True
            continue

        if spacing:
            kept.append(SPACE)
            spacing = False

        kept.append(char)

    return "".join(kept)


def _continues(page: Page, index: int) -> bool:
    """Whether a line continues an assignment in code: it holds something, and its first
    character is not in a comment or a string."""
    line = page.source[index]
    indent = _indent(line)

    return indent < len(line) and page.scan.states[page.scan.starts[index] + indent] == State.CODE


def _indent(line: str) -> int:
    """How many spaces a line starts with."""
    return len(line) - len(line.lstrip(SPACE))


def _shifted(line: str, shift: int) -> str:
    """A line moved right by shift columns, or left by as many as its indent allows."""
    if shift > 0:
        return SPACE * shift + line

    return line[min(-shift, _indent(line)):]


class Failure(Exception):
    """A file that could not be read or written: which one, what failed, and why."""

    def __init__(self, path: str, what: str, error: OSError) -> None:
        super().__init__(path, what, error)
        self.path = path
        self.what = what
        self.why = error.strerror or str(error)

    def line(self) -> str:
        """The error line for stderr."""
        return "%s: error: %s: %s: %s" % (PROGRAM, self.path, self.what, self.why)


def _read(path: str) -> str:
    """A file's text, with no translation of its line ends."""
    try:
        with open(
            path,
            READ_MODE,
            encoding=ENCODING,
            errors=UNDECODED,
            newline=NO_TRANSLATION,
        ) as handle:
            return handle.read()
    except OSError as error:
        raise Failure(path, CANNOT_READ, error) from error


def _rewritten(path: str, text: str) -> None:
    """Replace a file's text with text, all at once. A symbolic link is followed, so that the
    file it names is replaced, and the new file has the old file's mode."""
    real = os.path.realpath(path)
    partial = ""

    try:
        mode = stat.S_IMODE(os.stat(real).st_mode)
        descriptor, partial = tempfile.mkstemp(
            prefix=os.path.basename(real) + ".",
            suffix=PARTIAL,
            dir=os.path.dirname(real),
        )

        with os.fdopen(
            descriptor,
            WRITE_MODE,
            encoding=ENCODING,
            errors=UNDECODED,
            newline=NO_TRANSLATION,
        ) as handle:
            handle.write(text)

        os.chmod(partial, mode)
        os.replace(partial, real)
    except OSError as error:
        if partial:
            with contextlib.suppress(FileNotFoundError):
                os.unlink(partial)

        raise Failure(path, CANNOT_WRITE, error) from error


def _written(data: bytes) -> None:
    """Write bytes to stdout as they are, so that a byte which is not UTF-8 gets through."""
    sys.stdout.buffer.write(data)


def _handled(path: str, listing: bool, writing: bool) -> bool:
    """Format one file as the options say, and tell whether it would change."""
    text = _read(path)
    result = formatted(text)
    changed = result != text
    printing = not listing and not writing

    if printing:
        _written(result.encode(ENCODING, UNDECODED))
    elif changed and listing:
        _written(os.fsencode(path) + NEWLINE.encode(ENCODING))

    if changed and writing:
        _rewritten(path, result)

    return changed


def main() -> int:
    """Run the tool on the files of the command line, and return the exit status."""
    parser = argparse.ArgumentParser(
        description="Set the ::= of each block of ASN.1 assignments in one column.",
    )
    parser.add_argument("-w", action="store_true", help="rewrite each file in place")
    parser.add_argument("-l", action="store_true", help="list each file that would change")
    parser.add_argument("files", nargs="+", metavar="FILE")
    arguments = parser.parse_args()
    paths: list[str] = arguments.files

    changed, failed = False, False

    for path in paths:
        try:
            changed = _handled(path, bool(arguments.l), bool(arguments.w)) or changed
        except Failure as failure:
            sys.stderr.write(failure.line() + NEWLINE)
            failed = True

    sys.stdout.buffer.flush()

    if failed:
        return EXIT_FAILED

    if arguments.l and changed:
        return EXIT_CHANGED

    return 0


if __name__ == "__main__":
    sys.exit(main())
