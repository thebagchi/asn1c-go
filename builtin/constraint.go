// Package builtin holds the ASN.1 built-in types X.691 gives their own
// encodings, hand-written against lib/per.
//
// It is the worked example a generator has to reproduce: codegen.md states the
// shape every type here takes, and these files are what that shape looks like
// when a person writes it. The repetition between them is therefore deliberate
// and is not to be factored away, because generated code cannot share a helper
// that its generator does not know how to emit.
package builtin

import (
	"github.com/thebagchi/asn1c-go/lib/per"
)

// The bounds the constraints below are built from, quoted from X.691 clause 32
// and from X.680 clause 21.5. Zero and one are left as themselves: they are the
// bottom of a range rather than a number that means something.
const (
	CENTURY_MAX          = 99
	YEAR_IMMEDIATE_MIN   = 2005
	YEAR_IMMEDIATE_MAX   = 2020
	YEAR_NEAR_FUTURE_MIN = 2021
	YEAR_NEAR_FUTURE_MAX = 2276
	YEAR_NEAR_PAST_MIN   = 1749
	YEAR_NEAR_PAST_MAX   = 2004
	YEAR_CHOICE_MAX      = 3
	MONTH_MAX            = 12
	DAY_OF_MONTH_MAX     = 31
	DAY_OF_WEEK_MAX      = 7
	DAY_OF_YEAR_MAX      = 366
	WEEK_MAX             = 53
	HOURS_MAX            = 24
	MINUTES_MAX          = 59
	SECONDS_MAX          = 60
	DIFF_HOURS_MAX       = 15
	DIFF_MINUTES_MAX     = 59
	FRACTION_MAX         = 999
	DIGITS_MAX           = 3
	DURATION_YEARS_MAX   = 31
	DURATION_MONTHS_MAX  = 15
	DURATION_WEEKS_MAX   = 63
	DURATION_DAYS_MAX    = 31
	DURATION_HOURS_MAX   = 31
	DURATION_MINUTES_MAX = 63
	DURATION_SECONDS_MAX = 63
	REAL_BASE_MIN        = 2
	REAL_BASE_MAX        = 10
)

// The PER-visible constraints of the components these types are built from,
// named for the component rather than for its bounds, and shared by every
// encoding that carries it.
//
// They are package-level values rather than expressions at each call site for
// two reasons. The bounds are part of the type's definition, so a reader should
// meet them once with a name attached rather than a dozen times as a pair of
// numbers. And a Constraint built at a call site is built again on every call,
// where one built here is built once.
//
// Two duration components may hold the same bounds; the component each belongs
// to is what its name is for.
var (
	CONSTRAINT_UNCONSTRAINED = per.Unconstrained()
	CONSTRAINT_NON_NEGATIVE  = per.SemiConstrained(0)
	CONSTRAINT_AT_LEAST_ONE  = per.SemiConstrained(1)

	CONSTRAINT_CENTURY          = per.Constrained(0, CENTURY_MAX)
	CONSTRAINT_YEAR_IMMEDIATE   = per.Constrained(YEAR_IMMEDIATE_MIN, YEAR_IMMEDIATE_MAX)
	CONSTRAINT_YEAR_NEAR_FUTURE = per.Constrained(YEAR_NEAR_FUTURE_MIN, YEAR_NEAR_FUTURE_MAX)
	CONSTRAINT_YEAR_NEAR_PAST   = per.Constrained(YEAR_NEAR_PAST_MIN, YEAR_NEAR_PAST_MAX)
	CONSTRAINT_YEAR_CHOICE      = per.Constrained(0, YEAR_CHOICE_MAX)
	CONSTRAINT_MONTH            = per.Constrained(1, MONTH_MAX)
	CONSTRAINT_DAY_OF_MONTH     = per.Constrained(1, DAY_OF_MONTH_MAX)
	CONSTRAINT_DAY_OF_WEEK      = per.Constrained(1, DAY_OF_WEEK_MAX)
	CONSTRAINT_DAY_OF_YEAR      = per.Constrained(1, DAY_OF_YEAR_MAX)
	CONSTRAINT_WEEK             = per.Constrained(1, WEEK_MAX)

	CONSTRAINT_HOURS        = per.Constrained(0, HOURS_MAX)
	CONSTRAINT_MINUTES      = per.Constrained(0, MINUTES_MAX)
	CONSTRAINT_SECONDS      = per.Constrained(0, SECONDS_MAX)
	CONSTRAINT_DIFF_HOURS   = per.Constrained(0, DIFF_HOURS_MAX)
	CONSTRAINT_DIFF_MINUTES = per.Constrained(1, DIFF_MINUTES_MAX)
	CONSTRAINT_FRACTION     = per.Constrained(0, FRACTION_MAX).Extensible()
	CONSTRAINT_DIGITS       = per.Constrained(1, DIGITS_MAX).Extensible()

	CONSTRAINT_DURATION_YEARS   = per.Constrained(0, DURATION_YEARS_MAX).Extensible()
	CONSTRAINT_DURATION_MONTHS  = per.Constrained(0, DURATION_MONTHS_MAX).Extensible()
	CONSTRAINT_DURATION_WEEKS   = per.Constrained(0, DURATION_WEEKS_MAX).Extensible()
	CONSTRAINT_DURATION_DAYS    = per.Constrained(0, DURATION_DAYS_MAX).Extensible()
	CONSTRAINT_DURATION_HOURS   = per.Constrained(0, DURATION_HOURS_MAX).Extensible()
	CONSTRAINT_DURATION_MINUTES = per.Constrained(0, DURATION_MINUTES_MAX).Extensible()
	CONSTRAINT_DURATION_SECONDS = per.Constrained(0, DURATION_SECONDS_MAX).Extensible()

	CONSTRAINT_REAL_BASE = per.Constrained(REAL_BASE_MIN, REAL_BASE_MAX)
)
