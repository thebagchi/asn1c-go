package builtin

import (
	"github.com/thebagchi/asn1c-go/lib/per"
)

// RealType is the associated type of the ASN.1 REAL built-in type.
// It corresponds to the formal definition in X.680 clause 21.5:
//
//	RealType ::= SEQUENCE {
//	    mantissa INTEGER,
//	    base     INTEGER (2 | 10),
//	    exponent INTEGER
//	    -- The associated mathematical real number is "mantissa"
//	    -- multiplied by "base" raised to the power "exponent"
//	}
type RealType struct {
	Mantissa int64 `per:""`
	Base     int64 `per:"lb=2,ub=10"`
	Exponent int64 `per:""`
}

// MarshalPER encodes the RealType using Packed Encoding Rules onto encoder,
// so nested types can chain encoding onto a shared encoder. MarshalAPER/
// MarshalUPER create the encoder and call this.
//
// Revisions:
//   - 2026-07-05 18:20: initial creation
//   - 2026-09-22 06:43: takes its bounds from a per.Constraint, which replaced
//     the lb, ub and extensible parameters the encoder used to take
func (r *RealType) MarshalPER(encoder *per.Encoder) ([]byte, error) {
	// mantissa INTEGER — unconstrained
	if err := encoder.EncodeInteger(r.Mantissa, CONSTRAINT_UNCONSTRAINED); err != nil {
		return nil, err
	}

	// base INTEGER (2 | 10) — constrained lb=2, ub=10
	if err := encoder.EncodeInteger(r.Base, CONSTRAINT_REAL_BASE); err != nil {
		return nil, err
	}

	// exponent INTEGER — unconstrained
	if err := encoder.EncodeInteger(r.Exponent, CONSTRAINT_UNCONSTRAINED); err != nil {
		return nil, err
	}

	return encoder.Bytes(), nil
}

// MarshalAPER encodes the RealType using Aligned Packed Encoding Rules (APER).
//
// Revisions:
//   - 2026-07-05 18:20: initial creation
//   - 2026-09-22 06:43: takes its bounds from a per.Constraint, which replaced
//     the lb, ub and extensible parameters the encoder used to take
func (r *RealType) MarshalAPER() ([]byte, error) {
	encoder := per.NewAlignedEncoder()
	return r.MarshalPER(encoder)
}

// MarshalUPER encodes the RealType using Unaligned Packed Encoding Rules (UPER).
//
// Revisions:
//   - 2026-07-05 18:20: initial creation
//   - 2026-09-22 06:43: takes its bounds from a per.Constraint, which replaced
//     the lb, ub and extensible parameters the encoder used to take
func (r *RealType) MarshalUPER() ([]byte, error) {
	encoder := per.NewUnalignedEncoder()
	return r.MarshalPER(encoder)
}

// UnmarshalPER decodes the RealType using Packed Encoding Rules from
// decoder, so nested types can chain decoding off a shared decoder.
// UnmarshalAPER/UnmarshalUPER create the decoder and call this.
//
// Revisions:
//   - 2026-07-05 18:20: initial creation
//   - 2026-09-22 06:43: takes its bounds from a per.Constraint, which replaced
//     the lb, ub and extensible parameters the encoder used to take
func (r *RealType) UnmarshalPER(decoder *per.Decoder) error {
	// mantissa INTEGER — unconstrained
	mantissa, err := decoder.DecodeInteger(CONSTRAINT_UNCONSTRAINED)
	if err != nil {
		return err
	}

	r.Mantissa = mantissa

	// base INTEGER (2 | 10) — constrained lb=2, ub=10
	base, err := decoder.DecodeInteger(CONSTRAINT_REAL_BASE)
	if err != nil {
		return err
	}

	r.Base = base

	// exponent INTEGER — unconstrained
	exponent, err := decoder.DecodeInteger(CONSTRAINT_UNCONSTRAINED)
	if err != nil {
		return err
	}

	r.Exponent = exponent

	return nil
}

// UnmarshalAPER decodes the RealType using Aligned Packed Encoding Rules (APER).
//
// Revisions:
//   - 2026-07-05 18:20: initial creation
//   - 2026-09-22 06:43: takes its bounds from a per.Constraint, which replaced
//     the lb, ub and extensible parameters the encoder used to take
func (r *RealType) UnmarshalAPER(data []byte) error {
	decoder := per.NewAlignedDecoder(data)
	return r.UnmarshalPER(decoder)
}

// UnmarshalUPER decodes the RealType using Unaligned Packed Encoding Rules (UPER).
//
// Revisions:
//   - 2026-07-05 18:20: initial creation
//   - 2026-09-22 06:43: takes its bounds from a per.Constraint, which replaced
//     the lb, ub and extensible parameters the encoder used to take
func (r *RealType) UnmarshalUPER(data []byte) error {
	decoder := per.NewUnalignedDecoder(data)
	return r.UnmarshalPER(decoder)
}
