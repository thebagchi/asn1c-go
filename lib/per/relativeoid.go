package per

import (
	"fmt"
)

// EncodeRelativeOID encodes a RELATIVE-OID, per X.690 clause 8.20 and X.691
// clause 25: one subidentifier for each arc (clause 8.19.2) behind a length
// determinant. A RELATIVE-OID has one component or more (X.680 clause 33), so an
// empty value is refused, and so is a negative arc. Both give an error that wraps
// ErrValueOutOfRange.
//
// Revisions:
//   - 2026-10-19 11:38: initial creation (review P4-1)
func (e *Encoder) EncodeRelativeOID(arcs []int) error {
	if len(arcs) == 0 {
		return fmt.Errorf(
			"relative object identifier of no arcs: %w",
			ErrValueOutOfRange,
		)
	}

	var stack [OID_STACK_OCTETS]byte

	contents, err := _AppendArcs(
		stack[:0],
		arcs,
	)
	if err != nil {
		return err
	}

	return e.EncodeOctetString(
		contents,
		Unconstrained(),
	)
}

// DecodeRelativeOID reads a RELATIVE-OID, per X.690 clause 8.20 and X.691
// clause 25. A length of zero is refused for the reason in EncodeRelativeOID. An
// arc above math.MaxInt64 gives an error that wraps ErrValueOutOfRange. Padded or
// cut-short contents give ErrObjectIdentifier.
//
// Revisions:
//   - 2026-10-19 11:38: initial creation (review P4-1)
func (d *Decoder) DecodeRelativeOID() ([]int, error) {
	contents, err := d._DecodeContents()
	if err != nil {
		return nil, err
	}

	if len(contents) == 0 {
		return nil, fmt.Errorf(
			"no subidentifier: %w",
			ErrObjectIdentifier,
		)
	}

	return _ReadArcs(
		make(
			[]int,
			0,
			_CountSubidentifiers(contents),
		),
		contents,
	)
}
