package builtin

import (
	"fmt"

	"github.com/thebagchi/asn1c-go/lib/per"
)

// YearEncoding is the X.691 (02/2021) clause 32.2.3 YEAR-ENCODING type, used
// to PER-encode the year component of a DATE-family TIME value whose
// abstract values have one of the "Basic=Date Date=Y Year=Basic" or
// "Basic=Date Date=Y Year=Proleptic" property settings (X.691 Table 2,
// row 3), and as the "year" component of YEAR-MONTH-ENCODING,
// DATE-ENCODING, YEAR-DAY-ENCODING, YEAR-WEEK-ENCODING and
// YEAR-WEEK-DAY-ENCODING.
//
//	YEAR-ENCODING ::= CHOICE { -- 2 bits for choice determinant
//	    immediate   INTEGER (2005..2020), -- 4 bits
//	    near-future INTEGER (2021..2276), -- 8 bits
//	    near-past   INTEGER (1749..2004), -- 8 bits
//	    remainder   INTEGER (MIN..1748 | 2277..MAX)
//	}
//
// Modeled the same way protoc-gen-go represents a oneof field, as if
// generated from:
//
//	message YearEncoding {
//	  oneof choices {
//	    int64 immediate = 1;
//	    int64 near_future = 2;
//	    int64 near_past = 3;
//	    int64 remainder = 4;
//	  }
//	}
//
// Every CHOICE type in this package follows this same shape: an outer
// message struct with a oneof field typed as a sealed choice<Type>
// interface, and one wrapper type per alternative implementing that
// interface. YearEncoding alone owns the CHOICE index; each wrapper type's
// MarshalPER/UnmarshalPER only ever encodes/decodes its own bare value.
type YearEncoding struct {
	// Choices holds exactly one of the four alternatives below.
	//
	// Types that are valid to be assigned to Choices:
	//
	//	*YearEncoding_Immediate
	//	*YearEncoding_NearFuture
	//	*YearEncoding_NearPast
	//	*YearEncoding_Remainder
	Choices choiceYearEncoding
}

// GetChoices returns the oneof field, or nil if y is nil or unset.
func (y *YearEncoding) GetChoices() choiceYearEncoding {
	if y != nil {
		return y.Choices
	}
	return nil
}

// GetImmediate returns the "immediate" alternative's value, or 0 if that is not the set alternative.
func (y *YearEncoding) GetImmediate() int64 {
	if v, ok := y.GetChoices().(*YearEncoding_Immediate); ok {
		return int64(*v)
	}
	return 0
}

// GetNearFuture returns the "near-future" alternative's value, or 0 if that is not the set alternative.
func (y *YearEncoding) GetNearFuture() int64 {
	if v, ok := y.GetChoices().(*YearEncoding_NearFuture); ok {
		return int64(*v)
	}
	return 0
}

// GetNearPast returns the "near-past" alternative's value, or 0 if that is not the set alternative.
func (y *YearEncoding) GetNearPast() int64 {
	if v, ok := y.GetChoices().(*YearEncoding_NearPast); ok {
		return int64(*v)
	}
	return 0
}

// GetRemainder returns the "remainder" alternative's value, or 0 if that is not the set alternative.
func (y *YearEncoding) GetRemainder() int64 {
	if v, ok := y.GetChoices().(*YearEncoding_Remainder); ok {
		return int64(*v)
	}
	return 0
}

// Year returns the underlying year value regardless of which alternative
// is set, or 0 if y is nil or has no alternative set.
func (y *YearEncoding) Year() int64 {
	switch v := y.GetChoices().(type) {
	case *YearEncoding_Immediate:
		return int64(*v)
	case *YearEncoding_NearFuture:
		return int64(*v)
	case *YearEncoding_NearPast:
		return int64(*v)
	case *YearEncoding_Remainder:
		return int64(*v)
	default:
		return 0
	}
}

// choiceYearEncoding is the sealed interface implemented by each
// YEAR-ENCODING CHOICE alternative below (YearEncoding_Immediate,
// YearEncoding_NearFuture, YearEncoding_NearPast, YearEncoding_Remainder).
// The unexported choiceYearEncoding() marker method means only types
// declared in this package can implement the interface; Kind() stays
// exported since it's what encode/decode dispatch on (an interface call
// plus integer switch, instead of a runtime type switch over the concrete
// alternative types), and it's useful for external callers doing their own
// dispatch on an already-obtained value.
type choiceYearEncoding interface {
	Kind() YearEncodingKind
	choiceYearEncoding()
}

// YearEncodingKind identifies which YEAR-ENCODING CHOICE alternative is
// set. Values match the CHOICE index (X.691 clause 32.2.3 encodes this
// directly as a 2-bit constrained whole number), so encode/decode can use
// int64(kind) as the index with no extra translation.
type YearEncodingKind int64

const (
	YEAR_ENCODING_KIND_IMMEDIATE YearEncodingKind = iota
	YEAR_ENCODING_KIND_NEAR_FUTURE
	YEAR_ENCODING_KIND_NEAR_PAST
	YEAR_ENCODING_KIND_REMAINDER
)

// YearEncoding_Immediate is the "immediate" alternative: INTEGER (2005..2020), 4 bits.
type YearEncoding_Immediate int64

// YearEncoding_NearFuture is the "near-future" alternative: INTEGER (2021..2276), 8 bits.
type YearEncoding_NearFuture int64

// YearEncoding_NearPast is the "near-past" alternative: INTEGER (1749..2004), 8 bits.
type YearEncoding_NearPast int64

// YearEncoding_Remainder is the "remainder" alternative: INTEGER (MIN..1748 | 2277..MAX).
type YearEncoding_Remainder int64

func (v *YearEncoding_Immediate) Kind() YearEncodingKind {
	return YEAR_ENCODING_KIND_IMMEDIATE
}

// choiceYearEncoding is the unexported marker method that seals
// choiceYearEncoding: only types declared in this package can implement it.
func (v *YearEncoding_Immediate) choiceYearEncoding() {
	// Intentionally empty; its only purpose is sealing the interface.
}

func (v *YearEncoding_NearFuture) Kind() YearEncodingKind {
	return YEAR_ENCODING_KIND_NEAR_FUTURE
}

// choiceYearEncoding is the unexported marker method that seals
// choiceYearEncoding: only types declared in this package can implement it.
func (v *YearEncoding_NearFuture) choiceYearEncoding() {
	// Intentionally empty; its only purpose is sealing the interface.
}

func (v *YearEncoding_NearPast) Kind() YearEncodingKind {
	return YEAR_ENCODING_KIND_NEAR_PAST
}

// choiceYearEncoding is the unexported marker method that seals
// choiceYearEncoding: only types declared in this package can implement it.
func (v *YearEncoding_NearPast) choiceYearEncoding() {
	// Intentionally empty; its only purpose is sealing the interface.
}

func (v *YearEncoding_Remainder) Kind() YearEncodingKind {
	return YEAR_ENCODING_KIND_REMAINDER
}

// choiceYearEncoding is the unexported marker method that seals
// choiceYearEncoding: only types declared in this package can implement it.
func (v *YearEncoding_Remainder) choiceYearEncoding() {
	// Intentionally empty; its only purpose is sealing the interface.
}

// NewYearEncoding wraps an already-selected CHOICE alternative (one of
// *YearEncoding_Immediate, *YearEncoding_NearFuture, *YearEncoding_NearPast,
// *YearEncoding_Remainder) into a *YearEncoding.
func NewYearEncoding(choice choiceYearEncoding) *YearEncoding {
	return &YearEncoding{Choices: choice}
}

// MarshalPER encodes the YearEncoding using Packed Encoding Rules onto
// encoder: it writes the CHOICE index itself, then calls the related
// choice's own MarshalPER on the same encoder so nested types (e.g.
// YearMonthEncoding) can chain onto a shared encoder. MarshalAPER/
// MarshalUPER create the encoder and call this.
func (y *YearEncoding) MarshalPER(encoder *per.Encoder) ([]byte, error) {
	choice := y.GetChoices()
	if choice == nil {
		return nil, fmt.Errorf("YearEncoding: no alternative set")
	}

	kind := choice.Kind()

	// CHOICE index: constrained whole number [0..3] (2 bits, no extension marker)
	lb, ub := int64(0), int64(3)
	if err := encoder.EncodeChoiceId(int64(kind), &lb, &ub, false); err != nil {
		return nil, err
	}

	switch v := choice.(type) {
	case *YearEncoding_Immediate:
		return v.MarshalPER(encoder)
	case *YearEncoding_NearFuture:
		return v.MarshalPER(encoder)
	case *YearEncoding_NearPast:
		return v.MarshalPER(encoder)
	case *YearEncoding_Remainder:
		return v.MarshalPER(encoder)
	default:
		return nil, fmt.Errorf("YearEncoding: unknown alternative type %T", choice)
	}
}

// MarshalAPER encodes the YearEncoding using Aligned Packed Encoding Rules (APER).
func (y *YearEncoding) MarshalAPER() ([]byte, error) {
	encoder := per.NewEncoder(true)
	return y.MarshalPER(encoder)
}

// MarshalUPER encodes the YearEncoding using Unaligned Packed Encoding Rules (UPER).
func (y *YearEncoding) MarshalUPER() ([]byte, error) {
	encoder := per.NewEncoder(false)
	return y.MarshalPER(encoder)
}

// UnmarshalPER decodes the YearEncoding using Packed Encoding Rules from
// decoder: it reads the CHOICE index itself, then calls the related
// choice's own UnmarshalPER on the same decoder so nested types (e.g.
// YearMonthEncoding) can chain off a shared decoder. UnmarshalAPER/
// UnmarshalUPER create the decoder and call this.
func (y *YearEncoding) UnmarshalPER(decoder *per.Decoder) error {
	// CHOICE index: constrained whole number [0..3] (2 bits, no extension marker)
	lb, ub := int64(0), int64(3)
	index, err := decoder.DecodeChoiceId(&lb, &ub, false)
	if err != nil {
		return err
	}

	switch YearEncodingKind(index) {
	case YEAR_ENCODING_KIND_IMMEDIATE:
		var v YearEncoding_Immediate
		if err := v.UnmarshalPER(decoder); err != nil {
			return err
		}
		y.Choices = &v
	case YEAR_ENCODING_KIND_NEAR_FUTURE:
		var v YearEncoding_NearFuture
		if err := v.UnmarshalPER(decoder); err != nil {
			return err
		}
		y.Choices = &v
	case YEAR_ENCODING_KIND_NEAR_PAST:
		var v YearEncoding_NearPast
		if err := v.UnmarshalPER(decoder); err != nil {
			return err
		}
		y.Choices = &v
	case YEAR_ENCODING_KIND_REMAINDER:
		var v YearEncoding_Remainder
		if err := v.UnmarshalPER(decoder); err != nil {
			return err
		}
		y.Choices = &v
	default:
		return fmt.Errorf("YearEncoding: invalid choice kind %d", index)
	}

	return nil
}

// UnmarshalAPER decodes the YearEncoding using Aligned Packed Encoding Rules (APER).
func (y *YearEncoding) UnmarshalAPER(data []byte) error {
	decoder := per.NewDecoder(data, true)
	return y.UnmarshalPER(decoder)
}

// UnmarshalUPER decodes the YearEncoding using Unaligned Packed Encoding Rules (UPER).
func (y *YearEncoding) UnmarshalUPER(data []byte) error {
	decoder := per.NewDecoder(data, false)
	return y.UnmarshalPER(decoder)
}

// MarshalPER encodes the YearEncoding_Immediate's bare value (no CHOICE
// index) using Packed Encoding Rules onto encoder, so nested types can
// chain encoding onto a shared encoder. MarshalAPER/MarshalUPER create the
// encoder and call this.
func (v *YearEncoding_Immediate) MarshalPER(encoder *per.Encoder) ([]byte, error) {
	lb, ub := int64(2005), int64(2020)
	if err := encoder.EncodeInteger(int64(*v), &lb, &ub, false); err != nil {
		return nil, err
	}

	return encoder.Bytes(), nil
}

// MarshalAPER encodes the YearEncoding_Immediate using Aligned Packed Encoding Rules (APER).
func (v *YearEncoding_Immediate) MarshalAPER() ([]byte, error) {
	encoder := per.NewEncoder(true)
	return v.MarshalPER(encoder)
}

// MarshalUPER encodes the YearEncoding_Immediate using Unaligned Packed Encoding Rules (UPER).
func (v *YearEncoding_Immediate) MarshalUPER() ([]byte, error) {
	encoder := per.NewEncoder(false)
	return v.MarshalPER(encoder)
}

// UnmarshalPER decodes the YearEncoding_Immediate's bare value (no CHOICE
// index) using Packed Encoding Rules from decoder, so nested types can
// chain decoding off a shared decoder. UnmarshalAPER/UnmarshalUPER create
// the decoder and call this.
func (v *YearEncoding_Immediate) UnmarshalPER(decoder *per.Decoder) error {
	lb, ub := int64(2005), int64(2020)
	value, err := decoder.DecodeInteger(&lb, &ub, false)
	if err != nil {
		return err
	}
	*v = YearEncoding_Immediate(value)

	return nil
}

// UnmarshalAPER decodes the YearEncoding_Immediate using Aligned Packed Encoding Rules (APER).
func (v *YearEncoding_Immediate) UnmarshalAPER(data []byte) error {
	decoder := per.NewDecoder(data, true)
	return v.UnmarshalPER(decoder)
}

// UnmarshalUPER decodes the YearEncoding_Immediate using Unaligned Packed Encoding Rules (UPER).
func (v *YearEncoding_Immediate) UnmarshalUPER(data []byte) error {
	decoder := per.NewDecoder(data, false)
	return v.UnmarshalPER(decoder)
}

// MarshalPER encodes the YearEncoding_NearFuture's bare value (no CHOICE
// index) using Packed Encoding Rules onto encoder, so nested types can
// chain encoding onto a shared encoder. MarshalAPER/MarshalUPER create the
// encoder and call this.
func (v *YearEncoding_NearFuture) MarshalPER(encoder *per.Encoder) ([]byte, error) {
	lb, ub := int64(2021), int64(2276)
	if err := encoder.EncodeInteger(int64(*v), &lb, &ub, false); err != nil {
		return nil, err
	}

	return encoder.Bytes(), nil
}

// MarshalAPER encodes the YearEncoding_NearFuture using Aligned Packed Encoding Rules (APER).
func (v *YearEncoding_NearFuture) MarshalAPER() ([]byte, error) {
	encoder := per.NewEncoder(true)
	return v.MarshalPER(encoder)
}

// MarshalUPER encodes the YearEncoding_NearFuture using Unaligned Packed Encoding Rules (UPER).
func (v *YearEncoding_NearFuture) MarshalUPER() ([]byte, error) {
	encoder := per.NewEncoder(false)
	return v.MarshalPER(encoder)
}

// UnmarshalPER decodes the YearEncoding_NearFuture's bare value (no CHOICE
// index) using Packed Encoding Rules from decoder, so nested types can
// chain decoding off a shared decoder. UnmarshalAPER/UnmarshalUPER create
// the decoder and call this.
func (v *YearEncoding_NearFuture) UnmarshalPER(decoder *per.Decoder) error {
	lb, ub := int64(2021), int64(2276)
	value, err := decoder.DecodeInteger(&lb, &ub, false)
	if err != nil {
		return err
	}
	*v = YearEncoding_NearFuture(value)

	return nil
}

// UnmarshalAPER decodes the YearEncoding_NearFuture using Aligned Packed Encoding Rules (APER).
func (v *YearEncoding_NearFuture) UnmarshalAPER(data []byte) error {
	decoder := per.NewDecoder(data, true)
	return v.UnmarshalPER(decoder)
}

// UnmarshalUPER decodes the YearEncoding_NearFuture using Unaligned Packed Encoding Rules (UPER).
func (v *YearEncoding_NearFuture) UnmarshalUPER(data []byte) error {
	decoder := per.NewDecoder(data, false)
	return v.UnmarshalPER(decoder)
}

// MarshalPER encodes the YearEncoding_NearPast's bare value (no CHOICE
// index) using Packed Encoding Rules onto encoder, so nested types can
// chain encoding onto a shared encoder. MarshalAPER/MarshalUPER create the
// encoder and call this.
func (v *YearEncoding_NearPast) MarshalPER(encoder *per.Encoder) ([]byte, error) {
	lb, ub := int64(1749), int64(2004)
	if err := encoder.EncodeInteger(int64(*v), &lb, &ub, false); err != nil {
		return nil, err
	}

	return encoder.Bytes(), nil
}

// MarshalAPER encodes the YearEncoding_NearPast using Aligned Packed Encoding Rules (APER).
func (v *YearEncoding_NearPast) MarshalAPER() ([]byte, error) {
	encoder := per.NewEncoder(true)
	return v.MarshalPER(encoder)
}

// MarshalUPER encodes the YearEncoding_NearPast using Unaligned Packed Encoding Rules (UPER).
func (v *YearEncoding_NearPast) MarshalUPER() ([]byte, error) {
	encoder := per.NewEncoder(false)
	return v.MarshalPER(encoder)
}

// UnmarshalPER decodes the YearEncoding_NearPast's bare value (no CHOICE
// index) using Packed Encoding Rules from decoder, so nested types can
// chain decoding off a shared decoder. UnmarshalAPER/UnmarshalUPER create
// the decoder and call this.
func (v *YearEncoding_NearPast) UnmarshalPER(decoder *per.Decoder) error {
	lb, ub := int64(1749), int64(2004)
	value, err := decoder.DecodeInteger(&lb, &ub, false)
	if err != nil {
		return err
	}
	*v = YearEncoding_NearPast(value)

	return nil
}

// UnmarshalAPER decodes the YearEncoding_NearPast using Aligned Packed Encoding Rules (APER).
func (v *YearEncoding_NearPast) UnmarshalAPER(data []byte) error {
	decoder := per.NewDecoder(data, true)
	return v.UnmarshalPER(decoder)
}

// UnmarshalUPER decodes the YearEncoding_NearPast using Unaligned Packed Encoding Rules (UPER).
func (v *YearEncoding_NearPast) UnmarshalUPER(data []byte) error {
	decoder := per.NewDecoder(data, false)
	return v.UnmarshalPER(decoder)
}

// MarshalPER encodes the YearEncoding_Remainder's bare value (no CHOICE
// index) using Packed Encoding Rules onto encoder, so nested types can
// chain encoding onto a shared encoder. MarshalAPER/MarshalUPER create the
// encoder and call this.
func (v *YearEncoding_Remainder) MarshalPER(encoder *per.Encoder) ([]byte, error) {
	if err := encoder.EncodeInteger(int64(*v), nil, nil, false); err != nil {
		return nil, err
	}

	return encoder.Bytes(), nil
}

// MarshalAPER encodes the YearEncoding_Remainder using Aligned Packed Encoding Rules (APER).
func (v *YearEncoding_Remainder) MarshalAPER() ([]byte, error) {
	encoder := per.NewEncoder(true)
	return v.MarshalPER(encoder)
}

// MarshalUPER encodes the YearEncoding_Remainder using Unaligned Packed Encoding Rules (UPER).
func (v *YearEncoding_Remainder) MarshalUPER() ([]byte, error) {
	encoder := per.NewEncoder(false)
	return v.MarshalPER(encoder)
}

// UnmarshalPER decodes the YearEncoding_Remainder's bare value (no CHOICE
// index) using Packed Encoding Rules from decoder, so nested types can
// chain decoding off a shared decoder. UnmarshalAPER/UnmarshalUPER create
// the decoder and call this.
func (v *YearEncoding_Remainder) UnmarshalPER(decoder *per.Decoder) error {
	value, err := decoder.DecodeInteger(nil, nil, false)
	if err != nil {
		return err
	}
	*v = YearEncoding_Remainder(value)

	return nil
}

// UnmarshalAPER decodes the YearEncoding_Remainder using Aligned Packed Encoding Rules (APER).
func (v *YearEncoding_Remainder) UnmarshalAPER(data []byte) error {
	decoder := per.NewDecoder(data, true)
	return v.UnmarshalPER(decoder)
}

// UnmarshalUPER decodes the YearEncoding_Remainder using Unaligned Packed Encoding Rules (UPER).
func (v *YearEncoding_Remainder) UnmarshalUPER(data []byte) error {
	decoder := per.NewDecoder(data, false)
	return v.UnmarshalPER(decoder)
}
