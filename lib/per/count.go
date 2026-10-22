package per

import (
	"fmt"
)

// CONSTRAINT_UNBOUNDED is the size of a count outside the root of an extensible size, X.691
// 20.4: a semi-constrained length with a lower bound of zero. The count codec uses this one
// value, because a new constraint for each list moves to the heap.
var (
	CONSTRAINT_UNBOUNDED = _Unbounded()
)

// COUNT_RESERVATION_CAP is the most components that a decoder reserves ahead of the components
// that it decodes. A length in the input can be false, so no more than this is reserved
// before the input shows the components.
const (
	COUNT_RESERVATION_CAP = 1024
)

// Count is the position of a codec in the components of a SEQUENCE OF or SET OF, X.691 20 and
// 22. The encoding of 16K components or more has parts, and a length goes before each part,
// 11.9.3.8. The caller writes or reads the components from Start to End. While More is true,
// EncodeNext or DecodeNext then gives the next part.
//
// The caller keeps a Count on its stack and writes or reads the components in its own loop. A
// function value that writes them moves the encoder or the decoder to the heap.
//
// The size is kept as its bounds, a copy, so that a constraint that the caller builds for one
// call stays out of the heap. The fields are the lower and upper bound of the length, whether
// there is an upper bound, the number of components that the encoder writes, the indices of
// the part, and whether a length follows the part. A decoder does not know the number of
// components before the last part, so it does not use total.
type Count struct {
	total   uint64
	start   uint64
	end     uint64
	lower   uint64
	upper   uint64
	bounded bool
	more    bool
}

// Start returns the index of the first component of the part.
//
// Revisions:
//   - 2026-10-19 14:31: initial creation
func (c *Count) Start() int {
	return int(c.start)
}

// End returns the index after the last component of the part. It counts from the first
// component of the list, so it is the total after the last part.
//
// Revisions:
//   - 2026-10-19 14:31: initial creation
func (c *Count) End() int {
	return int(c.end)
}

// More tells if a length follows the part, X.691 11.9.3.8. A length follows each full part of
// 16K, 32K, 48K or 64K components, also when no component is left after it, 11.9.3.8.3.
//
// Revisions:
//   - 2026-10-19 14:31: initial creation
func (c *Count) More() bool {
	return c.more
}

// Reservation returns the number of components that a decoder may allocate before it decodes
// the part: all the components of the part, up to COUNT_RESERVATION_CAP. A false length on a
// short input then costs at most that many components.
//
// Revisions:
//   - 2026-10-19 14:31: initial creation
func (c *Count) Reservation() int {
	return int(min(
		c.end-c.start,
		COUNT_RESERVATION_CAP,
	))
}

// EncodeCount starts the encoding of total components under the size of their type, X.691 20.
// It writes the extension bit of an extensible size, 20.4, and the length of the first part,
// 20.6. A fixed count below 64K has no length, 20.5. A count outside the size is
// ErrValueOutOfRange.
//
// A count in the root uses the size itself, as 20.4 tells: "as if the extension marker is not
// present". A count outside it uses an unbounded length.
//
// Revisions:
//   - 2026-10-19 14:31: initial creation
func (e *Encoder) EncodeCount(
	count *Count,
	total uint64,
	size *Constraint,
) error {
	*count = Count{
		total: total,
	}

	if size.HasExtension() {
		outside := !size._CoversLength(total)

		if err := e.WriteExtensionBit(outside); err != nil {
			return err
		}

		if outside {
			size = CONSTRAINT_UNBOUNDED
		}
	}

	if err := size._CheckLength(total); err != nil {
		return err
	}

	count._Fit(size)

	fixed, isFixed := size.Fixed()
	if isFixed && fixed < MAX_CONSTRAINED_LENGTH {
		count.end = total

		return nil
	}

	return e._EncodePart(count)
}

// EncodeNext writes the length of the part after the current part, X.691 11.9.3.8.3.
//
// Revisions:
//   - 2026-10-19 14:31: initial creation
func (e *Encoder) EncodeNext(count *Count) error {
	count.start = count.end

	return e._EncodePart(count)
}

// DecodeCount starts the decoding of the components of a SEQUENCE OF or SET OF under the size
// of their type, X.691 20. It reads the extension bit of an extensible size, 20.4, and the
// length of the first part, 20.6. A fixed count below 64K has no length, 20.5.
//
// Revisions:
//   - 2026-10-19 14:31: initial creation
func (d *Decoder) DecodeCount(
	count *Count,
	size *Constraint,
) error {
	*count = Count{}

	if size.HasExtension() {
		outside, err := d.ReadExtensionBit()
		if err != nil {
			return err
		}

		if outside {
			size = CONSTRAINT_UNBOUNDED
		}
	}

	count._Fit(size)

	fixed, isFixed := size.Fixed()
	if isFixed && fixed < MAX_CONSTRAINED_LENGTH {
		count.end = fixed

		return nil
	}

	return d._DecodePart(count)
}

// DecodeNext reads the length of the part after the current part, X.691 11.9.3.8.3.
//
// Revisions:
//   - 2026-10-19 14:31: initial creation
func (d *Decoder) DecodeNext(count *Count) error {
	count.start = count.end

	return d._DecodePart(count)
}

// _EncodePart writes the length of the part that starts at count.start. It records the end of
// the part, and whether a length follows it.
//
// Revisions:
//   - 2026-10-19 14:31: initial creation
func (e *Encoder) _EncodePart(count *Count) error {
	var (
		left = count.total - count.start

		size = count._Size()

		pending, err = e.EncodeLengthDeterminant(
			left,
			size,
		)
	)
	if err != nil {
		return err
	}

	count.end = count.total - pending
	count.more = left >= FRAGMENT_SIZE && size._Fragments()

	return nil
}

// _DecodePart reads the length of the part that starts at count.start, and checks the count
// against the size. The check of the upper bound comes before the components of the part, so a
// decoder reads no component that the type does not permit. The lower bound applies when no
// length follows.
//
// Revisions:
//   - 2026-10-19 14:31: initial creation
func (d *Decoder) _DecodePart(count *Count) error {
	length, more, err := d.DecodeLengthDeterminant(count._Size())
	if err != nil {
		return err
	}

	count.end = count.start + length
	count.more = more

	if count.bounded && count.end > count.upper {
		return fmt.Errorf(
			"count %d above the upper bound %d: %w",
			count.end,
			count.upper,
			ErrValueOutOfRange,
		)
	}

	if !more && count.end < count.lower {
		return fmt.Errorf(
			"count %d below the lower bound %d: %w",
			count.end,
			count.lower,
			ErrValueOutOfRange,
		)
	}

	return nil
}

// _Fragments reports whether a length under the constraint can have fragments: it has no upper
// bound, or one of 64K or more, X.691 11.9.3.8.
//
// Revisions:
//   - 2026-10-19 14:31: initial creation
func (c *Constraint) _Fragments() bool {
	upper, bounded := c._SizeUpper()

	return !bounded || upper >= MAX_CONSTRAINED_LENGTH
}

// _Fit keeps the bounds of a length constraint in the Count.
//
// Revisions:
//   - 2026-10-19 14:31: initial creation
func (c *Count) _Fit(size *Constraint) {
	c.lower = size._SizeLower()
	c.upper, c.bounded = size._SizeUpper()
}

// _Size returns the length constraint that the bounds of the Count make. Both constructors are
// small enough to inline here and in the caller, which keeps the constraint on the stack.
//
// Revisions:
//   - 2026-10-19 14:31: initial creation
func (c *Count) _Size() *Constraint {
	if c.bounded {
		return Constrained(
			int64(c.lower),
			int64(c.upper),
		)
	}

	return SemiConstrained(int64(c.lower))
}
