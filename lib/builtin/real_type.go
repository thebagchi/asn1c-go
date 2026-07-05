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
func (r *RealType) MarshalPER(encoder *per.Encoder) ([]byte, error) {
	// mantissa INTEGER — unconstrained
	if err := encoder.EncodeInteger(r.Mantissa, nil, nil, false); err != nil {
		return nil, err
	}

	// base INTEGER (2 | 10) — constrained lb=2, ub=10
	lb, ub := int64(2), int64(10)
	if err := encoder.EncodeInteger(r.Base, &lb, &ub, false); err != nil {
		return nil, err
	}

	// exponent INTEGER — unconstrained
	if err := encoder.EncodeInteger(r.Exponent, nil, nil, false); err != nil {
		return nil, err
	}

	return encoder.Bytes(), nil
}

// MarshalAPER encodes the RealType using Aligned Packed Encoding Rules (APER).
func (r *RealType) MarshalAPER() ([]byte, error) {
	encoder := per.NewEncoder(true)
	return r.MarshalPER(encoder)
}

// MarshalUPER encodes the RealType using Unaligned Packed Encoding Rules (UPER).
func (r *RealType) MarshalUPER() ([]byte, error) {
	encoder := per.NewEncoder(false)
	return r.MarshalPER(encoder)
}

// UnmarshalPER decodes the RealType using Packed Encoding Rules from
// decoder, so nested types can chain decoding off a shared decoder.
// UnmarshalAPER/UnmarshalUPER create the decoder and call this.
func (r *RealType) UnmarshalPER(decoder *per.Decoder) error {
	// mantissa INTEGER — unconstrained
	mantissa, err := decoder.DecodeInteger(nil, nil, false)
	if err != nil {
		return err
	}
	r.Mantissa = mantissa

	// base INTEGER (2 | 10) — constrained lb=2, ub=10
	lb, ub := int64(2), int64(10)
	base, err := decoder.DecodeInteger(&lb, &ub, false)
	if err != nil {
		return err
	}
	r.Base = base

	// exponent INTEGER — unconstrained
	exponent, err := decoder.DecodeInteger(nil, nil, false)
	if err != nil {
		return err
	}
	r.Exponent = exponent

	return nil
}

// UnmarshalAPER decodes the RealType using Aligned Packed Encoding Rules (APER).
func (r *RealType) UnmarshalAPER(data []byte) error {
	decoder := per.NewDecoder(data, true)
	return r.UnmarshalPER(decoder)
}

// UnmarshalUPER decodes the RealType using Unaligned Packed Encoding Rules (UPER).
func (r *RealType) UnmarshalUPER(data []byte) error {
	decoder := per.NewDecoder(data, false)
	return r.UnmarshalPER(decoder)
}
