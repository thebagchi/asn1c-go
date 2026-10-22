package per

import (
	"fmt"
)

// _YearEncoding is YEAR-ENCODING, X.691 32.2.3: a CHOICE of four ranges of the year, which
// gives a 6-bit or a 10-bit encoding in the common cases. The encoder takes the range that holds
// the year. The decoder refuses a year of the last alternative that an earlier one holds.
type _YearEncoding struct {
	year int64
}

// _Set stores the year.
//
// Revisions:
//   - 2026-10-19 16:15: initial creation
func (v *_YearEncoding) _Set(year int64) {
	v.year = year
}

// _Encode writes the index of the alternative that holds the year, and the year in it, X.691
// 32.2.3 and clause 23.
//
// Revisions:
//   - 2026-10-19 16:15: initial creation
func (v *_YearEncoding) _Encode(e *Encoder) error {
	choice := v._Choose()

	if err := e.EncodeChoiceId(
		choice,
		CONSTRAINT_TIME_YEAR_CHOICE,
	); err != nil {
		return err
	}

	return e.EncodeInteger(
		v.year,
		_YearConstraint(choice),
	)
}

// _Decode reads the index of the alternative and the year in it, X.691 32.2.3 and clause 23.
//
// Revisions:
//   - 2026-10-19 16:15: initial creation
func (v *_YearEncoding) _Decode(d *Decoder) error {
	choice, err := d.DecodeChoiceId(CONSTRAINT_TIME_YEAR_CHOICE)
	if err != nil {
		return err
	}

	year, err := d.DecodeInteger(_YearConstraint(choice))
	if err != nil {
		return err
	}

	v.year = year

	if choice == TIME_YEAR_REMAINDER && v._Choose() != TIME_YEAR_REMAINDER {
		return fmt.Errorf(
			"year %d is not in the alternative remainder of YEAR-ENCODING: %w",
			year,
			ErrTimeValue,
		)
	}

	return nil
}

// _Choose returns the index of the alternative that holds the year: immediate (2005 to 2020),
// near-future (2021 to 2276), near-past (1749 to 2004), or remainder, X.691 32.2.3.
//
// Revisions:
//   - 2026-10-19 16:15: initial creation
func (v *_YearEncoding) _Choose() int64 {
	switch {
	case CONSTRAINT_TIME_YEAR_IMMEDIATE._Covers(v.year):
		return TIME_YEAR_IMMEDIATE
	case CONSTRAINT_TIME_YEAR_NEAR_FUTURE._Covers(v.year):
		return TIME_YEAR_NEAR_FUTURE
	case CONSTRAINT_TIME_YEAR_NEAR_PAST._Covers(v.year):
		return TIME_YEAR_NEAR_PAST
	default:
		return TIME_YEAR_REMAINDER
	}
}

// _YearConstraint returns the constraint of the INTEGER of the alternative with the index
// choice, X.691 32.2.3. The remainder has the values below 1749 and above 2276 of the
// constraint (MIN..1748 | 2277..MAX), which X.691 13.2.4 reads as no bounds.
//
// Revisions:
//   - 2026-10-19 16:15: initial creation
func _YearConstraint(choice int64) *Constraint {
	switch choice {
	case TIME_YEAR_IMMEDIATE:
		return CONSTRAINT_TIME_YEAR_IMMEDIATE
	case TIME_YEAR_NEAR_FUTURE:
		return CONSTRAINT_TIME_YEAR_NEAR_FUTURE
	case TIME_YEAR_NEAR_PAST:
		return CONSTRAINT_TIME_YEAR_NEAR_PAST
	default:
		return CONSTRAINT_TIME_YEAR_ANY
	}
}

// _AnyYearEncoding is ANY-YEAR-ENCODING, X.691 32.2.4: INTEGER (MIN..MAX).
type _AnyYearEncoding struct {
	year int64
}

// _Set stores the year.
//
// Revisions:
//   - 2026-10-19 16:15: initial creation
func (v *_AnyYearEncoding) _Set(year int64) {
	v.year = year
}

// _Encode writes the year as an unconstrained INTEGER, X.691 32.2.4 and 13.2.
//
// Revisions:
//   - 2026-10-19 16:15: initial creation
func (v *_AnyYearEncoding) _Encode(e *Encoder) error {
	return e.EncodeInteger(
		v.year,
		CONSTRAINT_TIME_YEAR_ANY,
	)
}

// _Decode reads the year as an unconstrained INTEGER, X.691 32.2.4 and 13.2.
//
// Revisions:
//   - 2026-10-19 16:15: initial creation
func (v *_AnyYearEncoding) _Decode(d *Decoder) error {
	year, err := d.DecodeInteger(CONSTRAINT_TIME_YEAR_ANY)
	if err != nil {
		return err
	}

	v.year = year

	return nil
}
