package per

import (
	"bytes"
	"encoding/asn1"
	"math"

	"github.com/thebagchi/asn1c-go/lib/bitbuffer"
)

// Decoder represents a PER decoder
type Decoder struct {
	codec   *bitbuffer.Codec
	aligned bool
}

// NewDecoder creates a new PER decoder from encoded data
// aligned: true for APER, false for UPER
func NewDecoder(data []byte, aligned bool) *Decoder {
	return &Decoder{
		codec:   bitbuffer.CreateReader(data),
		aligned: aligned,
	}
}

// DecodeConstrainedWholeNumber decodes a constrained whole number
// with lower bound lb and upper bound ub.
// Returns the decoded value n, or an error if decoding fails.
func (d *Decoder) DecodeConstrainedWholeNumber(lb, ub int64) (int64, error) {
	vr := ub - lb + 1

	// If range is 1, only one value is possible
	if vr == 1 {
		return lb, nil
	}

	if !d.aligned {
		// UNALIGNED: encode (n - lb) as non-negative-binary-integer
		// with minimum bits necessary to represent the range
		bits := BitsNonNegativeBinaryInteger(uint64(vr - 1))
		value, err := d.codec.Read(uint8(bits))
		if err != nil {
			return 0, err
		}
		return lb + int64(value), nil
	}

	// ALIGNED variant
	// 11.5.7.1: Bit-field case (range <= 255)
	if vr <= 0xFF {
		var bits int
		switch {
		case vr == 0x02:
			bits = 1
		case vr >= 0x03 && vr <= 0x04:
			bits = 2
		case vr >= 0x05 && vr <= 0x08:
			bits = 3
		case vr >= 0x09 && vr <= 0x10:
			bits = 4
		case vr >= 0x11 && vr <= 0x20:
			bits = 5
		case vr >= 0x21 && vr <= 0x40:
			bits = 6
		case vr >= 0x41 && vr <= 0x80:
			bits = 7
		case vr >= 0x81 && vr <= 0xFF:
			bits = 8
		}
		value, err := d.codec.Read(uint8(bits))
		if err != nil {
			return 0, err
		}
		return lb + int64(value), nil
	}

	// 11.5.7.2: One-octet case (range == 256) - octet-aligned
	if vr == 0x100 {
		if err := d.codec.Advance(); err != nil {
			return 0, err
		}
		value, err := d.codec.Read(8)
		if err != nil {
			return 0, err
		}
		return lb + int64(value), nil
	}

	// 11.5.7.3: Two-octet case (range 257-64K) - octet-aligned
	if vr >= 0x101 && vr <= 0x10000 {
		if err := d.codec.Advance(); err != nil {
			return 0, err
		}
		value, err := d.codec.Read(16)
		if err != nil {
			return 0, err
		}
		return lb + int64(value), nil
	}

	// 11.5.7.4: Indefinite length case (range > 64K)
	// Decode length determinant first, then octet-aligned value
	var (
		octetsRange = OctetsNonNegativeBinaryIntegerLength(uint64(ub - lb))
		lbRange     = uint64(1)
		ubRange     = uint64(octetsRange)
	)
	octets, _, err := d.DecodeLengthDeterminant(&lbRange, &ubRange)
	if err != nil {
		return 0, err
	}

	// 11.5.7.4: Value is octet-aligned
	if err := d.codec.Advance(); err != nil {
		return 0, err
	}
	value, err := d.codec.Read(uint8(octets * 8))
	if err != nil {
		return 0, err
	}
	return lb + int64(value), nil
}

// DecodeNormallySmallNonNegativeWholeNumber decodes a normally small non-negative whole number.
// This is used when a non-negative whole number is expected to be small but whose size
// is potentially unlimited due to the presence of an extension marker.
func (d *Decoder) DecodeNormallySmallNonNegativeWholeNumber() (uint64, error) {
	// Read 1 bit to determine the case
	bit, err := d.codec.Read(1)
	if err != nil {
		return 0, err
	}

	// 11.6.1: If the bit is 0, read 6-bit value
	if bit == 0 {
		value, err := d.codec.Read(6)
		if err != nil {
			return 0, err
		}
		return value, nil
	}

	// 11.6.2: If the bit is 1, decode as semi-constrained whole number with lb=0
	return d.DecodeSemiConstrainedWholeNumber(0)
}

// DecodeSemiConstrainedWholeNumber decodes a semi-constrained whole number
// with lower bound lb. The value can be arbitrarily large, so a length
// determinant is decoded to determine how many octets to read.
func (d *Decoder) DecodeSemiConstrainedWholeNumber(lb int64) (uint64, error) {
	// 11.7.4: octet-aligned in the ALIGNED variant only
	if d.aligned {
		if err := d.codec.Advance(); err != nil {
			return 0, err
		}
	}

	// Decode the length determinant (number of octets)
	octets, _, err := d.DecodeLengthDeterminant(nil, nil)
	if err != nil {
		return 0, err
	}

	// Must align before reading the value
	if err := d.codec.Advance(); err != nil {
		return 0, err
	}

	// Read the value (octets * 8 bits)
	value, err := d.codec.Read(uint8(octets * 8))
	if err != nil {
		return 0, err
	}

	return uint64(lb + int64(value)), nil
}

// DecodeUnconstrainedWholeNumber decodes an unconstrained whole number.
// This is used for INTEGER values with no bounds.
// The value is encoded as a 2's-complement-binary-integer in the minimum
// number of octets required to represent it.
func (d *Decoder) DecodeUnconstrainedWholeNumber() (int64, error) {
	// 11.8.3: octet-aligned in the ALIGNED variant only
	if d.aligned {
		if err := d.codec.Advance(); err != nil {
			return 0, err
		}
	}

	// Decode the length determinant (number of octets)
	octets, _, err := d.DecodeLengthDeterminant(nil, nil)
	if err != nil {
		return 0, err
	}

	// Read the value (octets * 8 bits) as 2's-complement
	value, err := d.codec.Read(uint8(octets * 8))
	if err != nil {
		return 0, err
	}

	// Convert from unsigned to signed (2's-complement)
	// If the most significant bit is set, this is a negative number
	if octets > 0 {
		msb := uint64(1) << (uint(octets*8) - 1)
		if value&msb != 0 {
			// Negative number: convert from 2's-complement
			// Create a mask for the bits we have
			mask := (uint64(1) << uint(octets*8)) - 1
			// Perform sign extension
			return -int64((^value & mask) + 1), nil
		}
	}

	// Positive number
	return int64(value), nil
}

// DecodeLengthDeterminant decodes a length determinant.
// If both lb and ub are provided and ub < MAX_CONSTRAINED_LENGTH, the length is decoded as a constrained whole number.
// Otherwise, it is decoded as an unconstrained length.
// Returns (length, hasMoreFragments, error).
func (d *Decoder) DecodeLengthDeterminant(lb, ub *uint64) (uint64, bool, error) {
	// 11.9.3.3 / 11.9.4.1: constrained when "ub" is less than MAX_CONSTRAINED_LENGTH
	if ub != nil && lb != nil && *ub < MAX_CONSTRAINED_LENGTH {
		value, err := d.DecodeConstrainedWholeNumber(int64(*lb), int64(*ub))
		if err != nil {
			return 0, false, err
		}
		return uint64(value), false, nil
	}

	// Otherwise, decode as unconstrained length
	return d.DecodeUnconstrainedLength()
}

// DecodeUnconstrainedLength decodes an unconstrained length determinant.
// This is used for unbounded length fields.
// Returns (length, hasMoreFragments, error):
// - hasMoreFragments is true if length == 63*16384, indicating more fragment octets follow
// - hasMoreFragments is false if this is the final length determinant
func (d *Decoder) DecodeUnconstrainedLength() (uint64, bool, error) {
	// 11.9.4.2: octet-aligned in the ALIGNED variant only
	if d.aligned {
		if err := d.codec.Advance(); err != nil {
			return 0, false, err
		}
	}

	// Read the first octet
	first, err := d.codec.Read(8)
	if err != nil {
		return 0, false, err
	}

	// 11.9.4.2: If most significant bit is 0, length is in range 0-127
	if first&0x80 == 0 {
		return first, false, nil
	}

	// 11.9.4.2: If most significant 2 bits are 10, length is in range 128-16383
	if first&0xC0 == 0x80 {
		second, err := d.codec.Read(8)
		if err != nil {
			return 0, false, err
		}
		// Combine first and second octets (remove the 10 prefix)
		length := ((first & 0x3F) << 8) | (second & 0xFF)
		return length, false, nil
	}

	// 11.9.4.2: If most significant 2 bits are 11, length is given in fragments
	// The next 6 bits indicate the number of fragments
	// Each fragment is FRAGMENT_SIZE bytes
	fragments := first & 0x3F
	length := uint64(fragments) * FRAGMENT_SIZE

	// If fragments == 63, there are more fragment octets following
	more := (fragments == 63)
	return length, more, nil
}

// DecodeNormallySmallLength decodes a normally small length determinant.
// This is used for lengths that are expected to be small (1-64) but can be larger.
// Returns (length, hasMoreFragments, error).
func (d *Decoder) DecodeNormallySmallLength() (uint64, bool, error) {
	// Read 1 bit to determine the case
	bit, err := d.codec.Read(1)
	if err != nil {
		return 0, false, err
	}

	// If bit is 0, length is in range 1-64 (encoded as 6 bits, value 0-63)
	if bit == 0 {
		value, err := d.codec.Read(6)
		if err != nil {
			return 0, false, err
		}
		// Value is n-1, so add 1 to get the original n
		return value + 1, false, nil
	}

	// If bit is 1, length is unconstrained, use DecodeUnconstrainedLength
	return d.DecodeUnconstrainedLength()
}

// DecodeBoolean decodes a boolean value.
// Per ITU-T X.691 Section 12, a boolean is encoded as a single bit:
// - 1 for TRUE
// - 0 for FALSE
func (d *Decoder) DecodeBoolean() (bool, error) {
	bit, err := d.codec.Read(1)
	if err != nil {
		return false, err
	}
	return bit != 0, nil
}

// DecodeInteger decodes an integer value with optional constraints and extensibility.
// Parameters:
// - lb: lower bound (nil if unconstrained)
// - ub: upper bound (nil if unconstrained)
// - extensible: whether the type has an extension marker
// Returns the decoded integer or an error.
func (d *Decoder) DecodeInteger(lb *int64, ub *int64, extensible bool) (int64, error) {
	if extensible {
		// Read extension bit
		extended, err := d.codec.Read(1)
		if err != nil {
			return 0, err
		}

		// If extended (bit = 1), decode as unconstrained
		if extended != 0 {
			return d.DecodeUnconstrainedWholeNumber()
		}
		// Otherwise, continue with normal constrained/unconstrained decoding
	}

	// If both bounds are equal, there's only one possible value
	if lb != nil && ub != nil && *lb == *ub {
		return *lb, nil
	}

	// If both lb and ub are set, decode as constrained whole number
	if lb != nil && ub != nil {
		return d.DecodeConstrainedWholeNumber(*lb, *ub)
	}

	// If only lb is set, decode as semi-constrained whole number
	if lb != nil && ub == nil {
		value, err := d.DecodeSemiConstrainedWholeNumber(*lb)
		if err != nil {
			return 0, err
		}
		return int64(value), nil
	}

	// Otherwise (no bounds), decode as unconstrained whole number
	return d.DecodeUnconstrainedWholeNumber()
}

// DecodeEnumerated decodes an enumerated value.
// Parameters:
// - count: the total number of enumeration values
// - extensible: whether the enumeration has an extension marker
// Returns the decoded enumeration index or an error.
func (d *Decoder) DecodeEnumerated(count uint64, extensible bool) (uint64, error) {
	if extensible {
		// Read extension bit
		extended, err := d.codec.Read(1)
		if err != nil {
			return 0, err
		}

		// If extended (bit = 1), decode as normally small non-negative whole number
		// and add count to get the original value
		if extended != 0 {
			value, err := d.DecodeNormallySmallNonNegativeWholeNumber()
			if err != nil {
				return 0, err
			}
			return value + count, nil
		}
		// Otherwise, continue with normal constrained decoding
	}

	// Decode as constrained whole number with lb=0 and ub=count-1
	lb := int64(0)
	ub := int64(count - 1)
	value, err := d.DecodeConstrainedWholeNumber(lb, ub)
	if err != nil {
		return 0, err
	}
	return uint64(value), nil
}

// DecodeReal decodes a real value (float64) following PER encoding rules per section 8.5
// Based on ITU-T X.690 specifications
func (d *Decoder) DecodeReal() (float64, error) {
	// Section 15.2: Content octets are preceded by an unconstrained length determinant
	if d.aligned {
		if err := d.codec.Advance(); err != nil {
			return 0, err
		}
	}

	length, _, err := d.DecodeUnconstrainedLength()
	if err != nil {
		return 0, err
	}

	// Section 8.5.2: Plus zero has length = 0
	if length == 0 {
		return 0.0, nil
	}

	// Read the contents octets
	contents, err := d.codec.ReadBytes(int(length))
	if err != nil {
		return 0, err
	}

	// Section 8.5.9: Special real values (length 1)
	if length == 1 {
		octet := contents[0]
		switch octet {
		case 0x40:
			return math.Inf(1), nil // PLUS-INFINITY
		case 0x41:
			return math.Inf(-1), nil // MINUS-INFINITY
		case 0x42:
			return math.NaN(), nil // NOT-A-NUMBER
		case 0x43:
			return math.Copysign(0, -1), nil // Minus zero
		}
	}

	// Section 8.5.7: Binary/decimal encoding for non-zero values
	// Parse first octet per section 8.5.6-8.5.7:
	// Bit 7: Binary encoding flag (1 for binary)
	// Bit 6: Sign bit S (1 if negative, 0 if positive)
	// Bits 5-4: Base B (00=base2, 01=base8, 10=base16, 11=base10)
	// Bits 3-2: Scaling factor F (usually 00)
	// Bits 1-0: Exponent format (0=1 octet, 1=2 octets, 2=3 octets, 3=length prefix)
	first := contents[0]

	// Extract all fields and initialize variables
	var (
		sign     = int64(1)
		base     = 2
		exponent int
		offset   = 1
		mantissa int64
	)

	if (first & 0x40) != 0 {
		sign = -1
	}

	// Extract and apply base (bits 5-4)
	switch (first >> 4) & 0x03 {
	case 0:
		base = 2
	case 1:
		base = 8
	case 2:
		base = 16
	case 3:
		base = 10
	}

	// Decode exponent based on format (bits 1-0)
	switch first & 0x03 {
	case 0:
		// Single octet exponent
		if offset+1 > int(length) {
			return 0, nil // Invalid format
		}
		exponent = int(int8(contents[offset]))
		offset = offset + 1
	case 1:
		// Two octets exponent (big-endian)
		if offset+2 > int(length) {
			return 0, nil // Invalid format
		}
		exponent = int(int16((uint16(contents[offset]) << 8) | uint16(contents[offset+1])))
		offset = offset + 2
	case 2:
		// Three octets exponent (big-endian)
		if offset+3 > int(length) {
			return 0, nil // Invalid format
		}
		raw := (uint32(contents[offset]) << 16) | (uint32(contents[offset+1]) << 8) | uint32(contents[offset+2])
		exponent = int(raw)
		if raw&0x800000 != 0 {
			// Negative: two's complement
			exponent = exponent - (1 << 24)
		}
		offset = offset + 3
	case 3:
		// Length prefix format: length octet followed by exponent octets
		if offset+1 > int(length) {
			return 0, nil // Invalid format
		}

		so := offset + 1
		eo := so + int(contents[offset])
		if eo > int(length) {
			return 0, nil // Invalid format
		}

		// Read exponent as big-endian two's complement
		raw := uint64(0)
		for o := so; o < eo; o++ {
			raw = (raw << 8) | uint64(contents[o])
		}

		// Convert from unsigned to signed
		exponent = int(raw)
		num := eo - so
		if raw&(1<<(uint(num*8)-1)) != 0 {
			// Negative: two's complement
			exponent = exponent - (1 << uint(num*8))
		}
		offset = eo
	}

	// Decode mantissa N as unsigned binary integer (remaining octets)
	if offset < int(length) {
		for i := offset; i < int(length); i++ {
			mantissa = (mantissa << 8) | int64(contents[i])
		}
	}

	// Apply sign to mantissa
	mantissa = mantissa * sign

	// Use MakeFloat64 to reconstruct the value from base^exponent * mantissa
	return MakeFloat64(mantissa, exponent, base), nil
}

// ReadBits reads bits from the codec and returns them as a byte slice.
// The bits are read in MSB-first order.
// Parameters:
// - count: number of bits to read
// Returns the read bytes or an error.
func (d *Decoder) ReadBits(count uint) ([]byte, error) {
	if count == 0 {
		return []byte{}, nil
	}

	// Calculate number of full bytes and remaining bits
	var (
		num    = count / 8
		buffer bytes.Buffer
	)

	if num > 0 {
		bytes, err := d.codec.ReadBytes(int(num))
		if err != nil {
			return nil, err
		}
		buffer.Write(bytes)
	}

	// Handle remaining bits
	remaining := count % 8
	if remaining > 0 {
		value, err := d.codec.Read(uint8(remaining))
		if err != nil {
			return nil, err
		}
		// Shift left to align the bits to the MSB position of the byte
		buffer.WriteByte(uint8(value << (8 - remaining)))
	}
	return buffer.Bytes(), nil
}

// DecodeBitString decodes a bitstring value with optional constraints and extensibility.
// Parameters:
// - lb: lower bound on bitstring length in bits (nil if unconstrained)
// - ub: upper bound on bitstring length in bits (nil if unconstrained)
// - extensible: whether the type has an extension marker
// Returns a pointer to an asn1.BitString or an error.
func (d *Decoder) DecodeBitString(lb *uint64, ub *uint64, extensible bool) (*asn1.BitString, error) {
	// 16.6 If extensible, read a bit indicating if the length is in the extension root
	if extensible {
		extended, err := d.codec.Read(1)
		if err != nil {
			return nil, err
		}

		if extended != 0 {
			// Extended: decode length as semi-constrained whole number with fragmentation
			zero := uint64(0)
			return d.DecodeBitStringFragments(&zero, nil)
		}
	}

	// 16.8 If constrained to zero length, return empty bitstring
	if ub != nil && *ub == 0 {
		return &asn1.BitString{}, nil
	}

	// 16.9 If fixed length <= 16 bits, read directly (no length determinant)
	if lb != nil && ub != nil && *lb == *ub && *ub <= 16 {
		data, err := d.ReadBits(uint(*ub))
		if err != nil {
			return nil, err
		}
		return &asn1.BitString{Bytes: data, BitLength: int(*ub)}, nil
	}

	// 16.10 If fixed length > 16 bits but < 64K, align then read (no length determinant)
	if lb != nil && ub != nil && *lb == *ub && *ub < 65536 {
		if d.aligned {
			if err := d.codec.Advance(); err != nil {
				return nil, err
			}
		}
		data, err := d.ReadBits(uint(*ub))
		if err != nil {
			return nil, err
		}
		return &asn1.BitString{Bytes: data, BitLength: int(*ub)}, nil
	}

	// 16.11 Otherwise, decode with length determinant (with fragmentation support)
	if d.aligned {
		if err := d.codec.Advance(); err != nil {
			return nil, err
		}
	}
	return d.DecodeBitStringFragments(lb, ub)
}

// DecodeBitStringFragments decodes a bitstring that may be fragmented.
// This handles the indefinite-length case where the bitstring is split into fragments.
func (d *Decoder) DecodeBitStringFragments(lb *uint64, ub *uint64) (*asn1.BitString, error) {
	if d.aligned {
		if err := d.codec.Advance(); err != nil {
			return nil, err
		}
	}

	var (
		count   uint64
		content bytes.Buffer
	)

	for {
		// Decode length determinant
		length, more, err := d.DecodeLengthDeterminant(lb, ub)
		if err != nil {
			return nil, err
		}

		// Read the bits for this fragment
		fragment, err := d.ReadBits(uint(length))
		if err != nil {
			return nil, err
		}

		// Write to buffer
		content.Write(fragment)
		count = count + length

		// If no more fragments, we're done
		if !more {
			break
		}

		// Align for next fragment
		if d.aligned {
			if err := d.codec.Advance(); err != nil {
				return nil, err
			}
		}
	}

	return &asn1.BitString{Bytes: content.Bytes(), BitLength: int(count)}, nil
}

// DecodeOctetString decodes an octet string value with optional constraints and extensibility.
// Parameters:
// - lb: lower bound on octet string length in bytes (nil if unconstrained)
// - ub: upper bound on octet string length in bytes (nil if unconstrained)
// - extensible: whether the type has an extension marker
// Returns a byte slice or an error.
func (d *Decoder) DecodeOctetString(lb *uint64, ub *uint64, extensible bool) ([]byte, error) {
	// 17.3 If extensible, read a bit indicating if the length is in the extension root
	if extensible {
		extended, err := d.codec.Read(1)
		if err != nil {
			return nil, err
		}

		if extended != 0 {
			// Extended: decode length as semi-constrained whole number with fragmentation
			zero := uint64(0)
			return d.DecodeOctetStringFragments(&zero, nil)
		}
	}

	// 17.5 If constrained to zero length, return empty octet string
	if ub != nil && *ub == 0 {
		return []byte{}, nil
	}

	// 17.6 If fixed length <= 2 octets, read directly (no length determinant)
	if lb != nil && ub != nil && *lb == *ub && *ub <= 2 {
		data := make([]byte, *ub)
		bytes, err := d.codec.ReadBytes(int(*ub))
		if err != nil {
			return nil, err
		}
		copy(data, bytes)
		return data, nil
	}

	// 17.7 If fixed length > 2 octets but < 64K, align then read (no length determinant)
	if lb != nil && ub != nil && *lb == *ub && *ub < 65536 {
		if d.aligned {
			if err := d.codec.Advance(); err != nil {
				return nil, err
			}
		}
		data := make([]byte, *ub)
		bytes, err := d.codec.ReadBytes(int(*ub))
		if err != nil {
			return nil, err
		}
		copy(data, bytes)
		return data, nil
	}

	// 17.8 Otherwise, decode with length determinant (with fragmentation support)
	return d.DecodeOctetStringFragments(lb, ub)
}

// DecodeOctetStringFragments decodes an octet string that may be fragmented.
// This handles the indefinite-length case where the octet string is split into fragments.
func (d *Decoder) DecodeOctetStringFragments(lb *uint64, ub *uint64) ([]byte, error) {
	if d.aligned {
		if err := d.codec.Advance(); err != nil {
			return nil, err
		}
	}

	var content bytes.Buffer

	for {
		// Decode length determinant
		length, more, err := d.DecodeLengthDeterminant(lb, ub)
		if err != nil {
			return nil, err
		}

		// Read the bytes for this fragment
		fragment, err := d.codec.ReadBytes(int(length))
		if err != nil {
			return nil, err
		}

		// Write to buffer
		content.Write(fragment)

		// If no more fragments, we're done
		if !more {
			break
		}

		// Align for next fragment
		if d.aligned {
			if err := d.codec.Advance(); err != nil {
				return nil, err
			}
		}
	}

	return content.Bytes(), nil
}

// DecodeNull decodes a NULL value.
// Per ITU-T X.691 Section 23, a NULL value never contributes any octets to the encoding.
// Therefore, there is nothing to decode, and this function simply returns nil.
func (d *Decoder) DecodeNull() error {
	return nil
}

// DecodeString decodes a string value with optional constraints and extensibility.
// This is suitable for restricted character string types where PER treats the value as an opaque octet string:
//   - VisibleString    (ISO 646, 1 byte/char, unconstrained alphabet)
//   - IA5String        (ISO 646, 1 byte/char, unconstrained alphabet)
//   - PrintableString  (ISO 646 subset, 1 byte/char, unconstrained alphabet)
//
// Parameters:
// - lb: lower bound on string length in bytes (nil if unconstrained)
// - ub: upper bound on string length in bytes (nil if unconstrained)
// - extensible: whether the type has an extension marker
// Returns the decoded string or an error.
func (d *Decoder) DecodeString(lb *uint64, ub *uint64, extensible bool) (string, error) {
	// Decode as octet string
	octets, err := d.DecodeOctetString(lb, ub, extensible)
	if err != nil {
		return "", err
	}

	// Convert octets to string
	return string(octets), nil
}
