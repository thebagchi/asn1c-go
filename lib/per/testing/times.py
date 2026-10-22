"""Oracle vectors for DATE, TIME-OF-DAY, DATE-TIME, DURATION and TIME (X.680 38; X.691 32).

Neither pycrate 0.8.1 nor Erlang/OTP 29.1.1 knows the time types (checked: both stop on the
type reference DATE, TIME-OF-DAY, DATE-TIME, DURATION and TIME as undefined, "native" in the
JSON). X.691 32.1.2 says a type whose abstract values have the property settings of a row of
Table 2 "shall be encoded as if the type with its constraints (if any) had been replaced by the
type specified in the corresponding row of column 3". So both oracles are asked for these
associated types, written in plain ASN.1 in testing.asn1 (the text of specs/builtin.asn1):

  DATE       Table 2 row 7, DATE-ENCODING (32.2.7)        probe DateProbe
  TIME-OF-DAY row 21, TIME-OF-DAY-ENCODING (32.3.7)       probe TimeOfDayProbe
  DATE-TIME  row 33 with rows 7 and 21 (32.4.1, 32.4.2)   probe DateTimeProbe
  DURATION   row 37, DURATION-INTERVAL-ENCODING (32.6.1)  probe DurationProbe
  TIME       32.1.4 note 2: always MIXED-ENCODING (32.11.5) probe MixedProbe

Both oracles must give the same octets for APER and UPER, or the run stops (no row needed a
pick). Three spellings of testing.asn1 differ from the text of the clause, and each one is the same type:
  - INTEGER (MIN..MAX) is written INTEGER (OTP stops on the range in a CHOICE alternative);
  - INTEGER (MIN..1748 | 2277..MAX) is written INTEGER (OTP stops on it too). Its bounds are
    MIN and MAX, so X.691 13.2.4 applies: the value is not restricted to a whole number with a bound. pycrate encodes the clause spelling and the plain
    one with the same octets for 14 years (checked, scratch run, not repeated here);
  - a type with two parameters that holds DATE-TIME-ENCODING {Date-Type, Time-Type} (the
    interval types of rows 36, 40, 43, 46, 50, 53) holds the SEQUENCE { date, time } that it
    defines. OTP does not stop on this one: it never ends. The expansion is the type of 32.4.1.

What the value of a row is (the decisions are in .agents/p9-tester.md):
  - TIME rows hold the time.Time that the codec takes, with a zone: "UTC" is time.UTC; "+HH:MM"
    is a fixed zone, also "+00:00".
  - A DURATION holds a time.Duration. Its elements are the hours, minutes and seconds that are
    not zero, and the least significant element (seconds when there is a fraction of a second,
    or when the value is zero), by 32.6.3. The fraction has the fewest digits, by 32.6.5.

Run: testing.py runs this module; see harness.py

Revisions:
  - 2026-10-19 15:55: initial creation
  - 2026-10-20 00:08: read testing.asn1 through harness.py; return the vectors, write no file
  - 2026-10-20 00:43: every row keeps the answers of both oracles, py and er for each variant, with
    expected and derived (see harness.py)
"""

import harness

KIND = "times"
PREFIX = "Times"
TAG = PREFIX + "-"

NS = 1_000_000_000

# Names of the clause rows used in the rows of the JSON.
CLAUSE_DATE = "X.691 32.1.2 Table 2 row 7, 32.2.7 (DATE-ENCODING, YEAR-ENCODING 32.2.3)"
CLAUSE_TOD = "X.691 32.1.2 Table 2 row 21, 32.3.7 (TIME-OF-DAY-ENCODING)"
CLAUSE_DT = "X.691 32.1.2 Table 2 row 33, 32.4.1, 32.4.2 (DATE-TIME-ENCODING {rows 7, 21})"
CLAUSE_DUR = "X.691 32.1.2 Table 2 row 37, 32.6.1 to 32.6.5 (DURATION-INTERVAL-ENCODING)"
CLAUSE_TIME = "X.691 32.1.4 note 2, 32.11.5 to 32.11.9 (MIXED-ENCODING row 33, DATE-TYPE, TIME-TYPE)"


# ---------------------------------------------------------------------------------------
# Values of the rows


def zone_offset(zone):
    """The offset in minutes of a zone text, or None for UTC."""
    if zone == "UTC":
        return None
    sign = -1 if zone[0] == "-" else 1
    return sign * (int(zone[1:3]) * 60 + int(zone[4:6]))


def fraction(ns):
    """(digits, value) of a fraction of nanoseconds with the fewest digits, X.691 32.11.9."""
    digits = 9
    while ns % 10 == 0:
        ns //= 10
        digits -= 1
    return digits, ns


def year_alt(year):
    """The alternative of YEAR-ENCODING (X.691 32.2.3) that holds a year."""
    if 2005 <= year <= 2020:
        return "immediate"
    if 2021 <= year <= 2276:
        return "near-future"
    if 1749 <= year <= 2004:
        return "near-past"
    return "remainder"


# Each builder returns (pycrate value, Erlang text).


def date_value(year, month, day):
    return (
        {"year": (year_alt(year), year), "month": month, "day": day},
        f"{{'{TAG}DATE-ENCODING',{{'{year_alt(year)}',{year}}},{month},{day}}}",
    )


def any_date_value(year, month, day):
    return {"year": year, "month": month, "day": day}, f"{{'{TAG}ANY-DATE-ENCODING',{year},{month},{day}}}"


def tod_value(hours, minutes, seconds):
    return (
        {"hours": hours, "minutes": minutes, "seconds": seconds},
        f"{{'{TAG}TIME-OF-DAY-ENCODING',{hours},{minutes},{seconds}}}",
    )


def diff_value(offset, negative_zero=False):
    """TIME-DIFFERENCE (32.3.3) of an offset in minutes."""
    sign = "negative" if offset < 0 or negative_zero else "positive"
    hours, minutes = divmod(abs(offset), 60)
    py = {"sign": sign, "hours": hours}
    erl_minutes = "asn1_NOVALUE"
    if minutes:
        py["minutes"] = minutes
        erl_minutes = str(minutes)
    return py, f"{{'{TAG}TIME-DIFFERENCE',{sign},{hours},{erl_minutes}}}"


def time_type_value(spec):
    """TIME-TYPE (32.11.8) of a time spec: row, h, m, s, digits, frac, offset (minutes)."""
    row = spec["row"]
    h, m, s = spec["h"], spec["m"], spec.get("s", 0)
    digits, frac = spec.get("digits"), spec.get("frac")
    name = f"row-{row}"
    if row == 15 or row == 16:
        inner = (h, str(h))
    elif row == 21 or row == 22:
        inner = tod_value(h, m, s)
        if row == 22:
            inner = (inner[0], inner[1].replace("TIME-OF-DAY-ENCODING", "TIME-OF-DAY-UTC-ENCODING"))
    elif row == 23:
        diff = diff_value(spec["offset"], spec.get("negative_zero", False))
        inner = (
            {"local-time": {"hours": h, "minutes": m, "seconds": s}, "time-difference": diff[0]},
            f"{{'{TAG}TIME-OF-DAY-AND-DIFF-ENCODING',{{'{TAG}TIME-OF-DAY-AND-DIFF-ENCODING_local-time',{h},{m},{s}}},{diff[1]}}}",
        )
    elif row == 30 or row == 31:
        tag = TAG + ("TIME-OF-DAY-AND-FRACTION-ENCODING" if row == 30 else "TIME-OF-DAY-UTC-AND-FRACTION-ENCODING")
        inner = ({"hours": h, "minutes": m, "seconds": s, "fraction": frac}, f"{{'{tag}',{h},{m},{s},{frac}}}")
    elif row == 32:
        diff = diff_value(spec["offset"])
        tag = TAG + "TIME-OF-DAY-AND-DIFF-AND-FRACTION-ENCODING"
        inner = (
            {"local-time": {"hours": h, "minutes": m, "seconds": s, "fraction": frac}, "time-difference": diff[0]},
            f"{{'{tag}',{{'{tag}_local-time',{h},{m},{s},{frac}}},{diff[1]}}}",
        )
    else:
        raise SystemExit(f"time row {row} is not built")
    py = {"time-type": (name, inner[0])}
    erl_digits = "asn1_NOVALUE"
    if 24 <= row <= 32:
        py["number-of-digits"] = digits
        erl_digits = str(digits)
    return py, f"{{'{TAG}TIME-TYPE',{erl_digits},{{'{name}',{inner[1]}}}}}"


def date_type_value(spec):
    """DATE-TYPE (32.11.7) of a date spec: row 1, 3, 7 or 8."""
    row = spec["row"]
    y, m, d = spec.get("y"), spec.get("m"), spec.get("d")
    if row == 7:
        inner = date_value(y, m, d)
    elif row == 8:
        inner = any_date_value(y, m, d)
    elif row == 3:
        inner = ((year_alt(y), y), f"{{'{year_alt(y)}',{y}}}")
    elif row == 1:
        inner = (y, str(y))
    else:
        raise SystemExit(f"date row {row} is not built")
    return (f"row-{row}", inner[0]), f"{{'row-{row}',{inner[1]}}}"


def mixed_value(spec):
    """MIXED-ENCODING (32.11.5) of a spec: row 33 with a date and a time, or another row alone."""
    if "date" in spec:
        date = date_type_value(spec["date"])
        time = time_type_value(spec["time"])
        return (
            ("row-33", {"date": date[0], "time": time[0]}),
            f"{{'row-33',{{'{TAG}DATE-TIME-ENCODING',{date[1]},{time[1]}}}}}",
        )
    row = spec["alone"]["row"]
    one = spec["alone"]
    if row == 7:
        value = date_value(one["y"], one["m"], one["d"])
    elif row == 8:
        value = any_date_value(one["y"], one["m"], one["d"])
    elif row == 21:
        value = tod_value(one["h"], one["m"], one["s"])
    elif row == 22:
        value = tod_value(one["h"], one["m"], one["s"])
        value = (value[0], value[1].replace("TIME-OF-DAY-ENCODING", "TIME-OF-DAY-UTC-ENCODING"))
    elif row == 31:
        tag = TAG + "TIME-OF-DAY-UTC-AND-FRACTION-ENCODING"
        value = (
            {
                "number-of-digits": one["digits"],
                "time-value": {"hours": one["h"], "minutes": one["m"], "seconds": one["s"], "fraction": one["frac"]},
            },
            f"{{'{TAG}FRACTIONAL-TIME',{one['digits']},{{'{tag}',{one['h']},{one['m']},{one['s']},{one['frac']}}}}}",
        )
    elif row == 37:
        value = duration_value(one["elements"])
    else:
        raise SystemExit(f"alone row {row} is not built")
    return (f"row-{row}", value[0]), f"{{'row-{row}',{value[1]}}}"


def duration_value(elements):
    """DURATION-INTERVAL-ENCODING (32.6.1) of a dict of elements and "frac": [digits, value]."""
    names = ["years", "months", "weeks", "days", "hours", "minutes", "seconds"]
    py = {name: elements[name] for name in names if name in elements}
    parts = [str(elements[name]) if name in elements else "asn1_NOVALUE" for name in names]
    if "frac" in elements:
        digits, value = elements["frac"]
        py["fractional-part"] = {"number-of-digits": digits, "fractional-value": value}
        parts.append(f"{{'{TAG}DURATION-INTERVAL-ENCODING_fractional-part',{digits},{value}}}")
    else:
        parts.append("asn1_NOVALUE")
    return py, "{'" + TAG + "DURATION-INTERVAL-ENCODING'," + ",".join(parts) + "}"


# ---------------------------------------------------------------------------------------
# The rows


def mixed_of(row):
    """The MIXED-ENCODING spec of a TIME row: the rows that 32.11.4 selects for its settings."""
    year = row["y"]
    date_row = 7 if 0 <= year <= 9999 else 8
    offset = zone_offset(row["zone"])
    ns = row["ns"]
    time = {"h": row["H"], "m": row["M"], "s": row["S"]}
    if ns:
        time["digits"], time["frac"] = fraction(ns)
    if offset is None:
        time["row"] = 31 if ns else 22
    else:
        time["row"] = 32 if ns else 23
        time["offset"] = offset
    return {"date": {"row": date_row, "y": year, "m": row["m"], "d": row["d"]}, "time": time}


def time_row(y, m, d, H, M, S, ns, zone, **extra):
    row = {"kind": "time", "y": y, "m": m, "d": d, "H": H, "M": M, "S": S, "ns": ns, "zone": zone}
    row.update(extra)
    row["mixed"] = row.get("mixed") or mixed_of(row)
    return row


def date_rows():
    ymd = [
        (1582, 1, 1), (1582, 10, 15), (1582, 12, 31), (1600, 2, 29), (1700, 1, 1), (1748, 12, 31),
        (1749, 1, 1), (1900, 6, 15), (1999, 12, 31), (2000, 2, 29), (2004, 12, 31), (2005, 1, 1),
        (2020, 12, 31), (2021, 1, 1), (2024, 2, 29), (2276, 12, 31), (2277, 1, 1), (2400, 2, 29),
        (5000, 7, 4), (9999, 12, 31), (2005, 1, 31), (2020, 6, 30), (2021, 12, 1),
    ]
    rows = [{"kind": "date", "y": y, "m": m, "d": d} for y, m, d in ymd]
    # The date is the date of the value in its own zone (a wall clock at midnight there).
    for zone in ("+05:30", "-08:00", "+00:00", "+14:00"):
        rows.append({"kind": "date", "y": 2020, "m": 12, "d": 31, "zone": zone})
    rows.append({"kind": "date", "y": 1582, "m": 1, "d": 1, "zone": "-08:00"})
    rows.append({"kind": "date", "y": 9999, "m": 12, "d": 31, "zone": "+14:00"})
    return rows


def tod_rows():
    seconds = [0, 1, 2, 59, 60, 61, 3599, 3600, 3601, 45296, 43200, 86399, 86400, 12 * 3600 + 34 * 60 + 56, 23 * 3600 + 59 * 60 + 59]
    return [{"kind": "tod", "seconds": s} for s in dict.fromkeys(seconds)]


def dt_rows():
    cases = [
        (1582, 1, 1, 0, 0, 0), (1999, 12, 31, 23, 59, 59), (2005, 1, 1, 0, 0, 0), (2020, 12, 31, 12, 34, 56),
        (2021, 1, 1, 0, 0, 1), (2276, 12, 31, 23, 59, 59), (2277, 1, 1, 12, 0, 0), (9999, 12, 31, 23, 59, 59),
        (2000, 2, 29, 6, 7, 8), (1700, 3, 4, 5, 6, 7), (2024, 7, 4, 15, 0, 0), (1749, 1, 1, 0, 0, 0),
    ]
    rows = [{"kind": "dt", "y": y, "m": m, "d": d, "H": H, "M": M, "S": S} for y, m, d, H, M, S in cases]
    # the wall clock of the value is sent, whatever its zone
    for zone in ("UTC", "+05:30", "-08:00", "+00:00", "+14:00", "-12:00"):
        rows.append({"kind": "dt", "y": 2020, "m": 12, "d": 31, "H": 12, "M": 34, "S": 56, "zone": zone})
    rows.append({"kind": "dt", "y": 2005, "m": 1, "d": 1, "H": 0, "M": 0, "S": 0, "zone": "+05:30"})
    rows.append({"kind": "dt", "y": 9999, "m": 12, "d": 31, "H": 23, "M": 59, "S": 59, "zone": "-08:00"})
    rows.append({"kind": "dt", "y": 1582, "m": 1, "d": 1, "H": 0, "M": 0, "S": 0, "zone": "+05:30"})
    return rows


def duration_elements(ns):
    """The elements of a duration in nanoseconds, by 32.6.3 to 32.6.5 (see the header)."""
    frac_ns = ns % NS
    total = ns // NS
    hours, rest = divmod(total, 3600)
    minutes, seconds = divmod(rest, 60)
    elements = {}
    if hours:
        elements["hours"] = hours
    if minutes:
        elements["minutes"] = minutes
    if seconds or frac_ns or not (hours or minutes):
        elements["seconds"] = seconds
    if frac_ns:
        # the fraction is of the least significant element, which is the seconds here
        digits, value = fraction(frac_ns)
        elements["frac"] = [digits, value]
    return elements


def dur_rows():
    values = [
        0, 1, 10, 1000, 1_000_000, 500_000_000, NS, NS + 1, 1_500_000_000, 2 * NS, 59 * NS,
        60 * NS, 61 * NS, 3599 * NS, 59 * 60 * NS + 59 * NS, 60 * 60 * NS, 60 * 60 * NS + 1,
        90 * 60 * NS, 3600 * NS + 30 * NS, 25 * 3600 * NS, 31 * 3600 * NS, 32 * 3600 * NS,
        1000 * 3600 * NS, 100000 * 3600 * NS, 63 * NS, 64 * NS, 2 * 60 * NS, 63 * 60 * NS, 64 * 60 * NS,
        (2562047 * 3600 + 47 * 60 + 16) * NS + 854775807,  # the largest time.Duration
        2562047 * 3600 * NS, 3600 * NS + 60 * NS + NS + 1,
    ]
    # fractions of 1..9 digits, alone and after whole seconds, hours and minutes
    for count in range(1, 10):
        frac = int("123456789"[:count]) * 10 ** (9 - count)
        values.append(frac)
        values.append(NS + frac)
        values.append(59 * 60 * NS + 59 * NS + frac)
        values.append(25 * 3600 * NS + frac)
    return [{"kind": "dur", "ns": ns, "elements": duration_elements(ns)} for ns in dict.fromkeys(values)]


YEARS = [
    -100000, -10000, -9999, -100, -1, 0, 1, 99, 100, 1581, 1582, 1583, 1748, 1749, 2004, 2005, 2020, 2021,
    2276, 2277, 9999, 10000, 12345, 100000, 292277026595, -292277022000,
]


def time_rows():
    rows = []
    # the year edges: row 7 for 0 to 9999, row 8 outside, with a UTC clock and an offset clock
    for year in YEARS:
        rows.append(time_row(year, 1, 1, 0, 0, 0, 0, "UTC"))
        rows.append(time_row(year, 12, 31, 23, 59, 59, 0, "-08:00"))
        rows.append(time_row(year, 6, 15, 12, 34, 56, 123456789, "+05:30"))
    # leap days
    for year in (2000, 2024, 1600, 2400, 1996, 0, -4, 12000):
        rows.append(time_row(year, 2, 29, 1, 2, 3, 0, "UTC"))
    # the zones, all with the same wall clock
    for zone in (
        "UTC", "+00:00", "+00:30", "-00:30", "+01:00", "-01:00", "+05:30", "-08:00", "+05:45", "-03:30",
        "+13:00", "+14:00", "-12:00", "+15:00", "-15:00", "+09:59", "-10:01",
    ):
        rows.append(time_row(2020, 12, 31, 12, 34, 56, 0, zone))
        rows.append(time_row(2020, 12, 31, 12, 34, 56, 500_000_000, zone))
    # the fractions of 1 to 9 digits, UTC and offset; the last digit is not zero
    for zone in ("UTC", "+05:30", "-08:00", "+00:00"):
        for count in range(1, 10):
            rows.append(time_row(2020, 12, 31, 12, 34, 56, int("123456789"[:count]) * 10 ** (9 - count), zone))
            rows.append(time_row(1999, 1, 2, 0, 0, 0, int(str(count) * count) * 10 ** (9 - count), zone))
    # the digits are the fewest: trailing zeros are not sent (1.500 is 1 digit)
    for ns in (500_000_000, 100_000_000, 120_000_000, 1_000_000, 10, 1, 999_999_999, 100, 1000, 2_000_000):
        rows.append(time_row(2020, 12, 31, 12, 34, 56, ns, "UTC"))
        rows.append(time_row(2020, 12, 31, 12, 34, 56, ns, "+05:30"))
    # clocks at the edges of the day
    for H, M, S, ns in (
        (0, 0, 0, 0), (0, 0, 0, 1), (23, 59, 59, 0), (23, 59, 59, 999_999_999), (12, 0, 0, 0), (1, 1, 1, 1_001_001),
    ):
        for zone in ("UTC", "-08:00"):
            rows.append(time_row(2005, 1, 1, H, M, S, ns, zone))
    # decode only: fractions with trailing zeros, which a time.Time cannot keep
    for digits, frac, ns in (
        (3, 500, 500_000_000), (9, 100_000_000, 100_000_000), (2, 0, 0), (3, 0, 0), (5, 12300, 123_000_000),
        (4, 1230, 123_000_000), (6, 100, 100_000),
    ):
        for zone in ("UTC", "-08:00"):
            row = time_row(2020, 12, 31, 12, 34, 56, ns, zone, decode_only=True)
            row["mixed"] = mixed_of(row)
            row["mixed"]["time"]["row"] = 31 if zone == "UTC" else 32
            row["mixed"]["time"]["digits"] = digits
            row["mixed"]["time"]["frac"] = frac
            if zone != "UTC":
                row["mixed"]["time"]["offset"] = zone_offset(zone)
            rows.append(row)
    return rows


def alone(row, **fields):
    spec = {"row": row}
    spec.update(fields)
    return {"alone": spec}


def with_time(date, time):
    return {"date": date, "time": time}


def refuse_time_rows():
    d7 = {"row": 7, "y": 2020, "m": 12, "d": 31}
    t22 = {"row": 22, "h": 12, "m": 34, "s": 56}
    rows = []

    def add(why, mixed):
        rows.append({"kind": "refuse_time", "why": why, "mixed": mixed})

    # the rows that a time.Time cannot hold (time rows of 32.3, date rows of 32.2, other main rows)
    add("local time of day (row 21)", with_time(d7, {"row": 21, "h": 12, "m": 34, "s": 56}))
    add("local time of day with a fraction (row 30)", with_time(d7, {"row": 30, "h": 12, "m": 34, "s": 56, "digits": 3, "frac": 500}))
    add("hours only (row 15)", with_time(d7, {"row": 15, "h": 12, "m": 0}))
    add("hours only, UTC (row 16)", with_time(d7, {"row": 16, "h": 12, "m": 0}))
    add("year only (row 3)", with_time({"row": 3, "y": 2020}, t22))
    add("century (row 1)", with_time({"row": 1, "y": 20}, t22))
    add("date alone (row 7)", alone(7, y=2020, m=12, d=31))
    add("any date alone (row 8)", alone(8, y=2020, m=12, d=31))
    add("time of day alone (row 21)", alone(21, h=12, m=34, s=56))
    add("time of day, UTC, alone (row 22)", alone(22, h=12, m=34, s=56))
    add("fractional time alone (row 31)", alone(31, h=12, m=34, s=56, digits=3, frac=500))
    add("duration (row 37)", alone(37, elements={"hours": 1}))
    # the fraction
    add("10 digits of fraction", with_time(d7, {"row": 31, "h": 12, "m": 34, "s": 56, "digits": 10, "frac": 1234567891}))
    add("12 digits of fraction", with_time(d7, {"row": 31, "h": 12, "m": 34, "s": 56, "digits": 12, "frac": 1}))
    add("10 digits, zeros at the end, offset", with_time(d7, {"row": 32, "h": 12, "m": 34, "s": 56, "digits": 10, "frac": 5000000000, "offset": 60}))
    add("fraction 10 with 1 digit", with_time(d7, {"row": 31, "h": 12, "m": 34, "s": 56, "digits": 1, "frac": 10}))
    add("fraction 1000 with 3 digits", with_time(d7, {"row": 31, "h": 12, "m": 34, "s": 56, "digits": 3, "frac": 1000}))
    add("fraction 100000 with 2 digits, offset", with_time(d7, {"row": 32, "h": 12, "m": 34, "s": 56, "digits": 2, "frac": 100000, "offset": -480}))
    # the calendar
    for y, m, d in ((2021, 2, 29), (2021, 2, 30), (2021, 4, 31), (2021, 6, 31), (1900, 2, 29), (2100, 2, 29), (2021, 11, 31), (2020, 2, 30)):
        add(f"{y}-{m:02d}-{d:02d} is not a date", with_time({"row": 7, "y": y, "m": m, "d": d}, t22))
    add("the year -3, month 2, day 29 is not a date (-3 is not a leap year)", with_time({"row": 8, "y": -3, "m": 2, "d": 29}, t22))
    # the clock
    add("hours 24", with_time(d7, {"row": 22, "h": 24, "m": 0, "s": 0}))
    add("hours 24, minutes 30", with_time(d7, {"row": 22, "h": 24, "m": 30, "s": 0}))
    add("hours 24, offset", with_time(d7, {"row": 23, "h": 24, "m": 0, "s": 0, "offset": 330}))
    add("seconds 60", with_time(d7, {"row": 22, "h": 23, "m": 59, "s": 60}))
    add("seconds 60, offset", with_time(d7, {"row": 23, "h": 23, "m": 59, "s": 60, "offset": -480}))
    add("hours 24 with a fraction", with_time(d7, {"row": 31, "h": 24, "m": 0, "s": 0, "digits": 1, "frac": 0}))
    # the offset
    add("negative zero offset (-00:00)", with_time(d7, {"row": 23, "h": 12, "m": 34, "s": 56, "offset": 0, "negative_zero": True}))
    add("offset +15:30", with_time(d7, {"row": 23, "h": 12, "m": 34, "s": 56, "offset": 15 * 60 + 30}))
    add("offset -15:59", with_time(d7, {"row": 23, "h": 12, "m": 34, "s": 56, "offset": -(15 * 60 + 59)}))
    add("offset +15:01", with_time(d7, {"row": 32, "h": 12, "m": 34, "s": 56, "digits": 1, "frac": 5, "offset": 15 * 60 + 1}))
    # the year against the row (Year=Basic or Proleptic: row 7; Negative or Large: row 8)
    add("row 7 with the year 10000", with_time({"row": 7, "y": 10000, "m": 1, "d": 1}, t22))
    add("row 7 with the year -1", with_time({"row": 7, "y": -1, "m": 1, "d": 1}, t22))
    add("row 7 with the year 100000", with_time({"row": 7, "y": 100000, "m": 1, "d": 1}, t22))
    add("row 8 with the year 2000", with_time({"row": 8, "y": 2000, "m": 1, "d": 1}, t22))
    add("row 8 with the year 0", with_time({"row": 8, "y": 0, "m": 1, "d": 1}, t22))
    add("row 8 with the year 9999", with_time({"row": 8, "y": 9999, "m": 12, "d": 31}, t22))
    return rows


def refuse_date_rows():
    rows = []
    for y, m, d, why in (
        (1581, 12, 31, "year 1581 is Proleptic, not Basic (X.680 38.2.1)"),
        (1, 1, 1, "year 1"),
        (0, 1, 1, "year 0"),
        (-1, 1, 1, "year -1"),
        (10000, 1, 1, "year 10000 needs row 8 (Large)"),
        (100000, 1, 1, "year 100000"),
        (2021, 2, 29, "not a leap year"),
        (2021, 4, 31, "April has 30 days"),
        (2021, 2, 30, "February has 28 or 29 days"),
        (2100, 2, 29, "2100 is not a leap year"),
    ):
        rows.append({"kind": "refuse_date", "y": y, "m": m, "d": d, "why": why})
    return rows


def refuse_tod_rows():
    rows = []
    for h, m, s, why in (
        (24, 0, 1, "24:00:01"), (24, 1, 0, "24:01:00"), (24, 59, 59, "24:59:59"), (23, 59, 60, "leap second"),
        (0, 0, 60, "00:00:60"), (12, 30, 60, "12:30:60"),
    ):
        rows.append({"kind": "refuse_tod", "H": h, "M": m, "S": s, "why": why})
    return rows


def refuse_dt_rows():
    rows = []
    for y, m, d, H, M, S, why in (
        (2020, 1, 1, 24, 0, 0, "hours 24: a time.Time has no end-of-day midnight"),
        (2020, 1, 1, 24, 30, 0, "24:30:00"),
        (2020, 1, 1, 23, 59, 60, "leap second"),
        (2020, 2, 30, 0, 0, 0, "February has 28 or 29 days"),
        (2021, 2, 29, 12, 0, 0, "not a leap year"),
        (1581, 12, 31, 0, 0, 0, "year 1581 is not Basic"),
        (10000, 1, 1, 0, 0, 0, "year 10000"),
        (0, 1, 1, 0, 0, 0, "year 0"),
        (2020, 4, 31, 0, 0, 0, "April has 30 days"),
    ):
        rows.append({"kind": "refuse_dt", "y": y, "m": m, "d": d, "H": H, "M": M, "S": S, "why": why})
    return rows


def refuse_dur_rows():
    rows = []

    def add(why, elements):
        rows.append({"kind": "refuse_dur", "why": why, "elements": elements})

    add("years (X.680 38.2.4: no fixed length)", {"years": 1})
    add("months", {"months": 1})
    add("weeks", {"weeks": 1})
    add("days", {"days": 1})
    add("years, months and days with a clock", {"years": 1, "months": 2, "days": 3, "hours": 4})
    add("days with hours", {"days": 1, "hours": 1})
    add("zero days", {"days": 0})
    add("no element", {})
    add("hours that a time.Duration cannot hold", {"hours": 2562048})
    add("the largest hours", {"hours": 2562047, "minutes": 47, "seconds": 17})
    add("minutes that a time.Duration cannot hold", {"minutes": 153722868})
    add("seconds that a time.Duration cannot hold", {"seconds": 9223372037})
    add("fraction 10 with 1 digit", {"seconds": 1, "frac": [1, 10]})
    add("fraction 1000 with 3 digits", {"seconds": 1, "frac": [3, 1000]})
    add("hours with a fraction that is not whole nanoseconds", {"hours": 0, "frac": [13, 1]})
    add("minutes with a fraction that is not whole nanoseconds", {"minutes": 1, "frac": [12, 1]})
    add("seconds with 10 digits that are not whole nanoseconds", {"seconds": 1, "frac": [10, 1]})
    add("a fraction that is not whole nanoseconds in the hours", {"hours": 1, "frac": [14, 7]})
    return rows


def accept_dur_rows():
    """Decode-only DURATION values: the element values that need no calendar. ns is what to expect."""
    rows = []

    def add(why, elements, ns):
        rows.append({"kind": "dur", "decode_only": True, "why": why, "elements": elements, "ns": ns})

    add("70 seconds", {"seconds": 70}, 70 * NS)
    add("90 minutes", {"minutes": 90}, 90 * 60 * NS)
    add("hours 1 and fraction .5 (the fraction is of the hours)", {"hours": 1, "frac": [1, 5]}, 5400 * NS)
    add("minutes 1 and fraction .5", {"minutes": 1, "frac": [1, 5]}, 90 * NS)
    add("hours 0 and fraction .25", {"hours": 0, "frac": [2, 25]}, 900 * NS)
    add("minutes 0 and fraction .50", {"minutes": 0, "frac": [2, 50]}, 30 * NS)
    add("hours 0 and a fraction of 1e-10 h (360 ns)", {"hours": 0, "frac": [10, 1]}, 360)
    add("trailing zeros: seconds 1.500", {"seconds": 1, "frac": [3, 500]}, 1_500_000_000)
    add("trailing zeros: seconds 0.000", {"seconds": 0, "frac": [3, 0]}, 0)
    add("hours 1 minutes 0 seconds 5 (a zero element that 32.6.3 leaves out)", {"hours": 1, "minutes": 0, "seconds": 5}, 3605 * NS)
    add("hours 1 and 2 minutes 3 seconds", {"hours": 1, "minutes": 2, "seconds": 3}, 3723 * NS)
    add("nine digits of fraction after minutes", {"minutes": 1, "frac": [9, 123456789]}, 60 * NS + 7407407340)
    return rows


# ---------------------------------------------------------------------------------------
# The questions to the oracles


def ask_value(row):
    """Return (probe type, pycrate value, Erlang text) of a row."""
    kind = row["kind"]
    if kind in ("date", "refuse_date"):
        value = date_value(row["y"], row["m"], row["d"])
        return "DateProbe", value[0], value[1]
    if kind in ("tod", "refuse_tod"):
        if kind == "tod":
            hours, rest = divmod(row["seconds"], 3600)
            minutes, seconds = divmod(rest, 60)
        else:
            hours, minutes, seconds = row["H"], row["M"], row["S"]
        value = tod_value(hours, minutes, seconds)
        return "TimeOfDayProbe", value[0], value[1]
    if kind in ("dt", "refuse_dt"):
        date = date_value(row["y"], row["m"], row["d"])
        time = tod_value(row["H"], row["M"], row["S"])
        return (
            "DateTimeProbe",
            {"date": date[0], "time": time[0]},
            f"{{'{TAG}DATE-TIME-ENCODING',{date[1]},{time[1]}}}",
        )
    if kind in ("dur", "refuse_dur"):
        value = duration_value(row["elements"])
        return "DurationProbe", value[0], value[1]
    value = mixed_value(row["mixed"])
    return "MixedProbe", value[0], value[1]


def pycrate_ask(module, name, value):
    try:
        obj = getattr(module, name)
        obj.set_val(value)
        return obj.to_aper().hex(), obj.to_uper().hex()
    except Exception as exc:  # pycrate gives no answer
        text = "error " + type(exc).__name__ + " " + str(exc)[:80]
        return text, text


def answers(rows):
    module = harness.pycrate_module(PREFIX)
    asked = [ask_value(row) for row in rows]
    py = [pycrate_ask(module, name, value) for name, value, _ in asked]
    otp = harness.otp_encode(PREFIX, [(name, text) for name, _, text in asked])
    out = []
    for row, (name, _, text), p, o in zip(rows, asked, py, otp):
        if p[0].startswith("error") or o[0].startswith("error"):
            raise SystemExit(f"no answer for {row}\n  probe {name} {text}\n  pycrate {p}\n  otp {o}")
        if p != o:
            raise SystemExit(f"oracles disagree on {row}\n  probe {name} {text}\n  pycrate {p}\n  otp {o}")
        item = dict(row)
        item["probe"] = name
        item.update(harness.compose(p, o))
        out.append(item)
    return out


CLAUSES = {
    "date": CLAUSE_DATE,
    "refuse_date": CLAUSE_DATE,
    "tod": CLAUSE_TOD,
    "refuse_tod": CLAUSE_TOD,
    "dt": CLAUSE_DT,
    "refuse_dt": CLAUSE_DT,
    "dur": CLAUSE_DUR,
    "refuse_dur": CLAUSE_DUR,
    "time": CLAUSE_TIME,
    "refuse_time": CLAUSE_TIME,
}


# The keys of a row in the JSON. Python builds a row with the short keys; the file spells them in full
# (Go reads keys without regard to case, so "m" and "M" must not be a pair).
RENAMES = {"y": "year", "m": "month", "d": "day", "H": "hour", "M": "minute", "S": "second"}


def native():
    """Record what the oracles say about the time types themselves (checked by hand, see header)."""
    return {
        "otp": "asn1ct:compile stops: the type references DATE, TIME-OF-DAY, DATE-TIME, DURATION and TIME are undefined",
        "pycrate": "compile_text stops: ASN1RefType to DATE, undefined (the same for the other four)",
        "decision": "the associated types of X.691 32.1.2 and 32.11 are asked in place of the time types",
    }


def vectors():
    sections = {
        "date": date_rows(),
        "tod": tod_rows(),
        "dt": dt_rows(),
        "dur": dur_rows() + accept_dur_rows(),
        "time": time_rows(),
        "refuse_date": refuse_date_rows(),
        "refuse_tod": refuse_tod_rows(),
        "refuse_dt": refuse_dt_rows(),
        "refuse_dur": refuse_dur_rows(),
        "refuse_time": refuse_time_rows(),
    }
    flat = [row for rows in sections.values() for row in rows]
    done = answers(flat)
    for row, item in zip(flat, done):
        item["clause"] = CLAUSES[row["kind"]]
    document = {"native": native()}
    for item in done:
        for old, new in RENAMES.items():
            if old in item:
                item[new] = item.pop(old)
    position = 0
    for name, rows in sections.items():
        document[name] = done[position : position + len(rows)]
        position += len(rows)
    return document
