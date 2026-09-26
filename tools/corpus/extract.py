#!/usr/bin/env python3
"""Download 3GPP specifications and extract the ASN.1 modules they carry.

A 3GPP protocol specification is a Word document with its ASN.1 written
inline, delimited by "-- ASN1START" and "-- ASN1STOP" comment markers. That
convention is what makes this possible: the markers say where the formal
notation begins and ends, so the modules can be lifted out without reading
the prose around them.

The extraction is done from word/document.xml directly rather than through a
converter, for one reason that matters: a Word paragraph stores an indent as a
<w:tab/> element and not as text, and a converter that drops those turns

    message      BCCH-BCH-MessageType

into "messageBCCH-BCH-MessageType", which is one identifier where ASN.1 needs
two. Everything else here is bookkeeping; that is the part to keep.

Usage:
    python3 extract.py            # download what is missing, then extract
    python3 extract.py --clean    # remove the downloaded archives

Output goes to testdata/3gpp/ at the root of the repository, one .asn1
file per specification.
Nothing here is imported by the module; it is run by hand when the corpus
should be refreshed.
"""

import io
import os
import re
import sys
import urllib.request
import zipfile
import xml.etree.ElementTree as ET

# The WordprocessingML namespace every element below is in.
WORD = "{http://schemas.openxmlformats.org/wordprocessingml/2006/main}"

# 3GPP refuses a request that does not name a browser.
AGENT = "Mozilla/5.0"

ARCHIVE = "https://www.3gpp.org/ftp/Specs/archive"

# The specifications to take, chosen for what they exercise rather than for
# coverage of 3GPP: the radio resource protocols for constructed types and
# extension markers at a size no hand-written module reaches, and the
# application protocols for information object classes, which they are built
# out of almost entirely.
SPECS = [
    # Radio resource control: the largest constructed types anywhere, with
    # extension markers and addition groups at every version boundary.
    ("36.331", "lte-rrc"),
    ("38.331", "nr-rrc"),
    # The application protocols, which are information object classes almost
    # end to end: a class per message, an object set per message's contents.
    ("25.413", "ranap"),
    ("36.413", "s1ap"),
    ("38.413", "ngap"),
    ("36.423", "x2ap"),
    ("38.423", "xnap"),
    ("38.473", "f1ap"),
    ("37.483", "e1ap"),
    ("36.443", "m2ap"),
    ("36.444", "m3ap"),
    # Positioning.
    ("36.455", "lppa"),
    ("38.455", "nrppa"),
]

# Read and found to carry nothing this can reach, kept here so that the next
# person does not spend the afternoon finding out again:
#
#   25.331  UTRAN RRC   ships as .doc, whose text is not XML
#   36.355  LPP         its document body holds no ASN.1 at all
#   29.002  MAP         25 DEFINITIONS and no END: the modules are not in
#                       word/document.xml, and the ROSE operations that make
#                       this specification worth having are in whatever part
#                       does hold them
#   24.080  SS          the same
#   33.108  LI          the same

HERE = os.path.dirname(os.path.abspath(__file__))
DOWNLOADS = os.path.join(HERE, "downloads")
TESTDATA = os.path.normpath(os.path.join(HERE, "..", "..", "testdata", "3gpp"))


def series(number):
    """The archive directory a specification number lives under."""
    return number.split(".")[0] + "_series"


def read(url):
    """Fetch a URL, naming a browser because 3GPP refuses anything else."""
    request = urllib.request.Request(url, headers={"User-Agent": AGENT})

    with urllib.request.urlopen(request, timeout=300) as response:
        return response.read()


def latest(number):
    """The newest release of a specification, from its archive listing.

    An archive holds one zip per release, named for the specification and
    the release - 29002-i50.zip. The release part sorts in the order the
    releases were made, digits before letters, which is the order 3GPP
    numbered them in, so the last one is the newest.
    """
    listing = read("%s/%s/%s/" % (ARCHIVE, series(number), number))
    stem = number.replace(".", "")

    releases = re.findall(
        (stem + r"-([0-9a-z]+)\.zip").encode(), listing, re.I
    )
    if not releases:
        raise ValueError("no releases listed for %s" % number)

    return "%s-%s" % (stem, max(releases).decode().lower())


def fetch(number):
    """Download a specification's newest archive, returning its path."""
    release = latest(number)
    path = os.path.join(DOWNLOADS, release + ".zip")
    if os.path.exists(path):
        return path

    url = "%s/%s/%s/%s.zip" % (ARCHIVE, series(number), number, release)

    os.makedirs(DOWNLOADS, exist_ok=True)
    with open(path, "wb") as handle:
        handle.write(read(url))

    return path


def paragraphs(document):
    """Every paragraph of a .docx, as the text a reader would see.

    The children are walked in document order so that an indent, which Word
    stores as an element rather than as text, keeps its place.
    """
    root = ET.fromstring(document.read("word/document.xml"))

    for para in root.iter(WORD + "p"):
        text = []

        for node in para.iter():
            if node.tag == WORD + "t":
                text.append(node.text or "")
            elif node.tag == WORD + "tab":
                text.append("\t")
            elif node.tag == WORD + "br":
                text.append("\n")

        yield "".join(text)


# A line opening ".$", which is how the older specifications mark a line of
# ASN.1 as hidden text so that Word numbers it the way Annex A does. The
# dollar sign is not an ASN.1 character at all, so removing the marker cannot
# take anything with it.
MARKER = re.compile(r"^\.\$", re.M)


# A module written out in full, which is how a specification too old for the
# markers carries its ASN.1. A name, the object identifier that may follow it,
# and DEFINITIONS are distinctive enough together that prose does not match
# them, and END is anchored to the start of a line so that the word inside a
# comment does not end a module early.
MODULE = re.compile(
    r"^[ \t]*([A-Z][A-Za-z0-9-]*)\s*(\{[^{}]*\})?\s*DEFINITIONS\b"
    r".*?\bBEGIN\b.*?^[ \t]*END\b",
    re.S | re.M,
)


def modules(path):
    """The ASN.1 held by the .docx inside an archive.

    Two specifications' worth of convention. The radio resource and newer
    application protocols mark their ASN.1 with ASN1START and ASN1STOP, which
    is exact. The older ones - RANAP is the one here - do not, and their
    modules are found by their own opening and closing words instead.
    """
    archive = zipfile.ZipFile(path)
    inner = [n for n in archive.namelist() if n.endswith(".docx")]
    if not inner:
        raise ValueError("ships as .doc, which is not XML")

    document = zipfile.ZipFile(io.BytesIO(archive.read(inner[0])))
    # The typography is put back before the markers are looked for, not
    # after: a marker written with a non-breaking space in it is not the
    # marker, and a block whose end is missed runs on into the prose.
    body = MARKER.sub("", normalize("\n".join(paragraphs(document))))

    blocks = re.findall(r"--\s*ASN1START(.*?)--\s*ASN1STOP", body, re.S)
    if not blocks:
        blocks = [match.group(0) for match in MODULE.finditer(body)]

    return trim("\n".join(blocks).strip()) + "\n"


# The last line that is nothing but END, which is where an ASN.1 file stops.
CLOSE = re.compile(r"(?s)^.*^[ \t]*END[ \t]*$", re.M)


def trim(text):
    """Cut whatever follows the last module.

    One specification - LPPa - has prose inside its own ASN1START and
    ASN1STOP markers, which the markers are supposed to keep out. Nothing
    written after the last END belongs to the ASN.1 either way, so the
    simplest reading of where the notation stops is the right one.
    """
    close = CLOSE.match(text)
    if close is None:
        return text

    return close.group(0)


# What a word processor puts in a document that ASN.1 has no character for.
# An ellipsis is the one that matters: X.680's extension marker is three full
# stops, and a specification written in Word has some of them autocorrected
# into a single character, which is then not the marker at all.
TYPOGRAPHY = {
    "\u2026": "...",
    "\u00a0": " ",
    "\u201c": '"',
    "\u201d": '"',
    "\u2018": "'",
    "\u2019": "'",
}


def normalize(text):
    """Put back the characters a word processor replaced."""
    for typography, plain in TYPOGRAPHY.items():
        text = text.replace(typography, plain)

    return text


def clean():
    """Remove the downloaded archives."""
    if not os.path.isdir(DOWNLOADS):
        return

    for name in os.listdir(DOWNLOADS):
        os.remove(os.path.join(DOWNLOADS, name))

    os.rmdir(DOWNLOADS)


def main():
    if "--clean" in sys.argv:
        clean()

        return

    os.makedirs(TESTDATA, exist_ok=True)

    for number, name in SPECS:
        try:
            archive = fetch(number)
            text = modules(archive)
        except Exception as error:
            print("%-10s %s" % (name, error))

            continue

        if len(text.strip()) == 0:
            print("%-10s %-12s no ASN.1 where this reads" % (name, number))

            continue

        out = os.path.join(TESTDATA, name + ".asn1")
        with open(out, "w") as handle:
            handle.write(text)

        print("%-10s %-12s %7d bytes" % (name, number, len(text)))


if __name__ == "__main__":
    main()
