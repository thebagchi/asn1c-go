package builtin

import (
	"github.com/thebagchi/asn1c-go/lib/per"
)

// AnyCenturyEncoding is the X.691 (02/2021) clause 32.2.2 ANY-CENTURY-ENCODING
// type, used to PER-encode the century component of a DATE-family TIME value
// whose abstract values have one of the "Basic=Date Date=C Year=Negative" or
// "Basic=Date Date=C Year=Ln" (for any n) property settings (X.691 Table 2,
// row 2).
//
//	ANY-CENTURY-ENCODING ::= INTEGER (MIN..MAX)
//
// The integer value is set to the value specified by the year component of
// the abstract value, ignoring the last two digits.
type AnyCenturyEncoding int64

// MarshalPER encodes the AnyCenturyEncoding using Packed Encoding Rules onto
// encoder, so nested types can chain encoding onto a shared encoder.
// MarshalAPER/MarshalUPER create the encoder and call this.
func (a *AnyCenturyEncoding) MarshalPER(encoder *per.Encoder) ([]byte, error) {
	// ANY-CENTURY-ENCODING ::= INTEGER (MIN..MAX) — unconstrained
	if err := encoder.EncodeInteger(int64(*a), nil, nil, false); err != nil {
		return nil, err
	}

	return encoder.Bytes(), nil
}

// MarshalAPER encodes the AnyCenturyEncoding using Aligned Packed Encoding Rules (APER).
func (a *AnyCenturyEncoding) MarshalAPER() ([]byte, error) {
	encoder := per.NewEncoder(true)
	return a.MarshalPER(encoder)
}

// MarshalUPER encodes the AnyCenturyEncoding using Unaligned Packed Encoding Rules (UPER).
func (a *AnyCenturyEncoding) MarshalUPER() ([]byte, error) {
	encoder := per.NewEncoder(false)
	return a.MarshalPER(encoder)
}

// UnmarshalPER decodes the AnyCenturyEncoding using Packed Encoding Rules
// from decoder, so nested types can chain decoding off a shared decoder.
// UnmarshalAPER/UnmarshalUPER create the decoder and call this.
func (a *AnyCenturyEncoding) UnmarshalPER(decoder *per.Decoder) error {
	// ANY-CENTURY-ENCODING ::= INTEGER (MIN..MAX) — unconstrained
	value, err := decoder.DecodeInteger(nil, nil, false)
	if err != nil {
		return err
	}
	*a = AnyCenturyEncoding(value)

	return nil
}

// UnmarshalAPER decodes the AnyCenturyEncoding using Aligned Packed Encoding Rules (APER).
func (a *AnyCenturyEncoding) UnmarshalAPER(data []byte) error {
	decoder := per.NewDecoder(data, true)
	return a.UnmarshalPER(decoder)
}

// UnmarshalUPER decodes the AnyCenturyEncoding using Unaligned Packed Encoding Rules (UPER).
func (a *AnyCenturyEncoding) UnmarshalUPER(data []byte) error {
	decoder := per.NewDecoder(data, false)
	return a.UnmarshalPER(decoder)
}
