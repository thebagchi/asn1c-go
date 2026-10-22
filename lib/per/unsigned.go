package per

import (
	"fmt"
)

// UnsignedConstraint is the range of an INTEGER above int64 (X.691 clauses
// 11.5, 11.7 and 13). The range is lb..ub, or lb..MAX when it has no upper
// bound. It has no extension marker.
//
// The fields hold the bounds as uint64, so 0..2^64-1 fits. The size of the range
// (2^64 values) does not, and the encoder never forms it: it works on ub - lb.
//
// Revisions:
//   - 2026-10-19 11:38: initial creation
type UnsignedConstraint struct {
	lb      uint64
	ub      uint64
	bounded bool
}

// Unsigned returns the constraint lb..ub, a constrained whole number (X.691
// clause 11.5). A pair with lb above ub holds no value.
//
// Revisions:
//   - 2026-10-19 11:38: initial creation
func Unsigned(
	lb,
	ub uint64,
) *UnsignedConstraint {
	return &UnsignedConstraint{
		lb:      lb,
		ub:      ub,
		bounded: true,
	}
}

// SemiUnsigned returns the constraint lb..MAX, a semi-constrained whole number
// (X.691 clause 11.7).
//
// Revisions:
//   - 2026-10-19 11:38: initial creation
func SemiUnsigned(lb uint64) *UnsignedConstraint {
	return &UnsignedConstraint{
		lb: lb,
	}
}

// EncodeUnsigned encodes an INTEGER above int64, per X.691 clauses 11.5 and 11.7.
// A bounded constraint selects the constrained whole number field of clause 11.5
// and a semi-constrained one the offset of clause 11.7 behind a length
// determinant (11.9). A nil constraint is lb 0 with no upper bound. A value
// outside the range has no encoding and gives ErrValueOutOfRange.
//
// Revisions:
//   - 2026-10-19 11:38: initial creation
func (e *Encoder) EncodeUnsigned(
	value uint64,
	root *UnsignedConstraint,
) error {
	if root == nil {
		root = SemiUnsigned(0)
	}

	if value < root.lb || (root.bounded && value > root.ub) {
		return fmt.Errorf(
			"unsigned value outside %d..: %w",
			root.lb,
			ErrValueOutOfRange,
		)
	}

	offset := value - root.lb

	if root.bounded {
		return e._EncodeOffset(
			root.ub-root.lb,
			offset,
		)
	}

	return e._EncodeOctetAligned(
		OctetsNonNegativeBinaryIntegerLength(offset),
		offset,
	)
}

// DecodeUnsigned reads an INTEGER above int64, per X.691 clauses 11.5 and 11.7.
// An offset above the range, and a semi-constrained value above 2^64-1, are
// errors that wrap ErrValueOutOfRange.
//
// Revisions:
//   - 2026-10-19 11:38: initial creation
func (d *Decoder) DecodeUnsigned(root *UnsignedConstraint) (uint64, error) {
	if root == nil {
		root = SemiUnsigned(0)
	}

	if root.bounded {
		if root.ub < root.lb {
			return 0, fmt.Errorf(
				"unsigned range %d..%d: %w",
				root.lb,
				root.ub,
				ErrValueOutOfRange,
			)
		}

		offset, err := d._DecodeOffset(root.ub - root.lb)

		return root.lb + offset, err
	}

	offset, _, err := d._ReadOctetAligned()
	if err != nil {
		return 0, err
	}

	if root.lb+offset < root.lb {
		return 0, fmt.Errorf(
			"offset %d above %d: %w",
			offset,
			root.lb,
			ErrValueOutOfRange,
		)
	}

	return root.lb + offset, nil
}
