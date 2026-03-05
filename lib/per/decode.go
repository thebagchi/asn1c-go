package per

import (
	"bytes"
	"encoding/asn1"
	"fmt"
	"math"
	"reflect"

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

	// 11.7.4: octet-aligned in the ALIGNED variant only
	if d.aligned {
		if err := d.codec.Advance(); err != nil {
			return 0, err
		}
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

	// Fragmentation marker always means more length determinants follow
	// (either another fragment or a terminating length <= 16383)
	return length, true, nil
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
	return d.DecodeBitStringFragments(lb, ub)
}

// DecodeBitStringFragments decodes a bitstring that may be fragmented.
// This handles the indefinite-length case where the bitstring is split into fragments.
func (d *Decoder) DecodeBitStringFragments(lb *uint64, ub *uint64) (*asn1.BitString, error) {
	// Only align at entry for unconstrained/semi-constrained length determinant paths
	// (11.9.3.5-11.9.3.8). For constrained paths (11.9.3.3), DecodeConstrainedWholeNumber
	// handles its own alignment per section 11.5.
	if d.aligned {
		if ub == nil || lb == nil {
			if err := d.codec.Advance(); err != nil {
				return nil, err
			}
		}
		if ub != nil && lb != nil {
			if *ub >= MAX_CONSTRAINED_LENGTH {
				if err := d.codec.Advance(); err != nil {
					return nil, err
				}
			}
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

		// In ALIGNED variant, octet-align before reading data
		if d.aligned {
			if err := d.codec.Advance(); err != nil {
				return nil, err
			}
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
	// Only align at entry for unconstrained/semi-constrained length determinant paths
	// (11.9.3.5-11.9.3.8). For constrained paths (11.9.3.3), DecodeConstrainedWholeNumber
	// handles its own alignment per section 11.5.
	if d.aligned {
		if ub == nil || lb == nil {
			if err := d.codec.Advance(); err != nil {
				return nil, err
			}
		}
		if ub != nil && lb != nil {
			if *ub >= MAX_CONSTRAINED_LENGTH {
				if err := d.codec.Advance(); err != nil {
					return nil, err
				}
			}
		}
	}

	var content bytes.Buffer

	for {
		// Decode length determinant
		length, more, err := d.DecodeLengthDeterminant(lb, ub)
		if err != nil {
			return nil, err
		}

		// In ALIGNED variant, octet-align before reading data
		if d.aligned {
			if err := d.codec.Advance(); err != nil {
				return nil, err
			}
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

// DecodeSequence decodes a SEQUENCE value per ITU-T X.691 section 19.
//
// The target must be a pointer to a struct. Fields are decoded according to
// their PER struct tags and the pre-computed StructMeta.
//
// Decoding steps:
//  1. §19.1: If extensible, decode extension bit
//  2. §19.2-19.3: Decode root preamble bitmap (one bit per OPTIONAL/DEFAULT field)
//  3. §19.4: Decode root component values in order
//  4. §19.6-19.9: If extension bit is set, decode extension bitmap then each
//     present extension addition as an open type
func (d *Decoder) DecodeSequence(value any) error {
	rv := reflect.ValueOf(value)
	if rv.Kind() != reflect.Pointer || rv.IsNil() {
		return fmt.Errorf("DecodeSequence: expected non-nil pointer, got %T", value)
	}
	rv = rv.Elem()
	if rv.Kind() != reflect.Struct {
		return fmt.Errorf("DecodeSequence: expected pointer to struct, got pointer to %s", rv.Kind())
	}

	rt := rv.Type()

	// --- Phase 1: Get cached struct metadata ---
	meta, err := GetStructMeta(rt)
	if err != nil {
		return fmt.Errorf("DecodeSequence: %w", err)
	}

	// --- Phase 2: Decode extension bit (section 19.1) ---
	hasExtensions := false
	if meta.Extensible {
		hasExtensions, err = d.DecodeBoolean()
		if err != nil {
			return fmt.Errorf("DecodeSequence: extension bit: %w", err)
		}
	}

	// --- Phase 3: Decode root preamble bitmap (section 19.2-19.3) ---
	// One bit per OPTIONAL/DEFAULT field: 1 = present, 0 = absent.
	optPresent := make(map[int]bool, len(meta.Optionals))
	for _, idx := range meta.Optionals {
		present, err := d.DecodeBoolean()
		if err != nil {
			return fmt.Errorf("DecodeSequence: root preamble: %w", err)
		}
		optPresent[idx] = present
	}

	// --- Phase 4: Decode root component values (section 19.4) ---
	for _, id := range meta.Fields {
		field := rt.Field(id)
		tag, err := GetFieldTag(field, rt, id)
		if err != nil {
			return fmt.Errorf("DecodeSequence: field %q: %w", field.Name, err)
		}

		// Skip absent optional/default fields
		if tag.Opt || tag.Def != nil {
			if !optPresent[id] {
				continue
			}
		}

		if err := d.decodeField(rv.Field(id), tag); err != nil {
			return fmt.Errorf("DecodeSequence: field %q: %w", field.Name, err)
		}
	}

	// --- Phase 5: Decode extension additions (sections 19.6-19.9) ---
	if !meta.Extensible || !hasExtensions {
		return nil
	}

	// Section 19.7-19.8: Decode extension bitmap preceded by normally-small-length
	extCount, _, err := d.DecodeNormallySmallLength()
	if err != nil {
		return fmt.Errorf("DecodeSequence: extension bitmap length: %w", err)
	}

	// Decode presence bitmap for extensions
	extPresent := make([]bool, extCount)
	for i := range extCount {
		extPresent[i], err = d.DecodeBoolean()
		if err != nil {
			return fmt.Errorf("DecodeSequence: extension bitmap: %w", err)
		}
	}

	// Section 19.9: Decode each present extension addition as open type
	for i := range extCount {
		if !extPresent[i] {
			continue
		}

		// Decode open type wrapper: unconstrained octet string
		openBytes, err := d.DecodeOctetString(nil, nil, false)
		if err != nil {
			return fmt.Errorf("DecodeSequence: extension %d: %w", i, err)
		}

		// If we have a known extension field for this index, decode into it
		if int(i) < len(meta.Extensions) {
			idx := meta.Extensions[i]
			field := rt.Field(idx)
			tag, err := GetFieldTag(field, rt, idx)
			if err != nil {
				return fmt.Errorf("DecodeSequence: extension field %q: %w", field.Name, err)
			}

			tmpDecoder := NewDecoder(openBytes, d.aligned)
			if err := tmpDecoder.decodeField(rv.Field(idx), tag); err != nil {
				return fmt.Errorf("DecodeSequence: extension field %q: %w", field.Name, err)
			}
		}
		// Unknown extensions (index >= len(meta.Extensions)) are silently skipped
	}

	return nil
}

// DecodeSequenceOf decodes a SEQUENCE OF value per ITU-T X.691 section 20.
//
// The target must be a pointer to a slice. Each element is decoded in order.
// lb/ub constrain the number of components; extensible indicates an extension marker.
//
// Decoding steps:
//  1. §20.4: If extensible, decode extension bit. If set, decode as semi-constrained
//     length + all components.
//  2. §20.5: If fixed length (lb==ub) and < 64K, no length determinant — just decode components.
//  3. §20.6: Decode length determinant (constrained if ub set, semi-constrained otherwise)
//     with fragmentation support, then decode components.
func (d *Decoder) DecodeSequenceOf(target any, lb *uint64, ub *uint64, extensible bool, elemTag *Tag) error {
	rv := reflect.ValueOf(target)
	if rv.Kind() != reflect.Pointer || rv.IsNil() {
		return fmt.Errorf("DecodeSequenceOf: expected non-nil pointer, got %T", target)
	}
	rv = rv.Elem()
	if rv.Kind() != reflect.Slice {
		return fmt.Errorf("DecodeSequenceOf: expected pointer to slice, got pointer to %s", rv.Kind())
	}

	elemType := rv.Type().Elem()

	// §20.4: If extensible, decode extension bit
	if extensible {
		extended, err := d.DecodeBoolean()
		if err != nil {
			return fmt.Errorf("DecodeSequenceOf: extension bit: %w", err)
		}

		if extended {
			// Decode as semi-constrained: length with lb=0, then components
			zero := uint64(0)
			return d.decodeSequenceOfComponents(rv, elemType, &zero, nil, elemTag)
		}
	}

	// §20.5: Fixed length (lb == ub) and < 64K — no length determinant
	if lb != nil && ub != nil && *lb == *ub && *ub < MAX_CONSTRAINED_LENGTH {
		n := int(*ub)
		for i := range n {
			elem := reflect.New(elemType).Elem()
			if err := d.decodeField(elem, elemTag); err != nil {
				return fmt.Errorf("DecodeSequenceOf: element %d: %w", i, err)
			}
			rv.Set(reflect.Append(rv, elem))
		}
		return nil
	}

	// §20.6: Length determinant + components (with fragmentation)
	return d.decodeSequenceOfComponents(rv, elemType, lb, ub, elemTag)
}

// decodeSequenceOfComponents decodes length determinant(s) and components,
// handling fragmentation per §11.9 for large lists.
func (d *Decoder) decodeSequenceOfComponents(rv reflect.Value, elemType reflect.Type, lb *uint64, ub *uint64, elemTag *Tag) error {
	for {
		length, more, err := d.DecodeLengthDeterminant(lb, ub)
		if err != nil {
			return fmt.Errorf("DecodeSequenceOf: length: %w", err)
		}

		for i := range int(length) {
			elem := reflect.New(elemType).Elem()
			if err := d.decodeField(elem, elemTag); err != nil {
				return fmt.Errorf("DecodeSequenceOf: element %d: %w", i, err)
			}
			rv.Set(reflect.Append(rv, elem))
		}

		if !more {
			break
		}
	}

	return nil
}

// DecodeChoice decodes a CHOICE value per ITU-T X.691 section 23.
//
// The target must be a pointer to a struct with fields tagged `per:"choice=N"`.
// Exactly one field will be set after decoding.
//
// Decoding steps:
//  1. If extensible (§23.5): decode extension bit
//  2. Root (§23.6/23.7): decode choice index as constrained integer [0..n],
//     then decode the chosen alternative
//  3. Extension (§23.8): decode choice index as normally small non-negative whole number,
//     then decode value as open type field (§11.2)
func (d *Decoder) DecodeChoice(value any) error {
	rv := reflect.ValueOf(value)
	if rv.Kind() != reflect.Pointer || rv.IsNil() {
		return fmt.Errorf("DecodeChoice: expected non-nil pointer, got %T", value)
	}
	rv = rv.Elem()
	if rv.Kind() != reflect.Struct {
		return fmt.Errorf("DecodeChoice: expected pointer to struct, got pointer to %s", rv.Kind())
	}

	rt := rv.Type()

	meta, err := GetStructMeta(rt)
	if err != nil {
		return fmt.Errorf("DecodeChoice: %w", err)
	}

	n := int64(len(meta.Fields) - 1) // largest root index

	// --- Section 23.5: Extension bit ---
	extended := false
	if meta.Extensible {
		extended, err = d.DecodeBoolean()
		if err != nil {
			return fmt.Errorf("DecodeChoice: extension bit: %w", err)
		}
	}

	if !extended {
		// --- Section 23.4/23.6/23.7: Root alternative ---
		var choiceIdx int64
		if n > 0 {
			choiceIdx, err = d.DecodeConstrainedWholeNumber(0, n)
			if err != nil {
				return fmt.Errorf("DecodeChoice: index: %w", err)
			}
		}

		if int(choiceIdx) >= len(meta.Fields) {
			return fmt.Errorf("DecodeChoice: root index %d out of range (max %d)", choiceIdx, len(meta.Fields)-1)
		}

		fieldIdx := meta.Fields[choiceIdx]
		field := rt.Field(fieldIdx)
		tag, err := GetFieldTag(field, rt, fieldIdx)
		if err != nil {
			return fmt.Errorf("DecodeChoice: field %q: %w", field.Name, err)
		}

		// Allocate pointer field if needed
		fv := rv.Field(fieldIdx)
		if fv.Kind() == reflect.Pointer {
			fv.Set(reflect.New(fv.Type().Elem()))
		}

		return d.decodeField(fv, tag)
	}

	// --- Section 23.8: Extension alternative ---
	extIdx, err := d.DecodeNormallySmallNonNegativeWholeNumber()
	if err != nil {
		return fmt.Errorf("DecodeChoice: extension index: %w", err)
	}

	// Decode open type wrapper
	openBytes, err := d.DecodeOctetString(nil, nil, false)
	if err != nil {
		return fmt.Errorf("DecodeChoice: extension open type: %w", err)
	}

	if int(extIdx) >= len(meta.Extensions) {
		// Unknown extension — silently skip (already consumed the bytes)
		return nil
	}

	fieldIdx := meta.Extensions[extIdx]
	field := rt.Field(fieldIdx)
	tag, err := GetFieldTag(field, rt, fieldIdx)
	if err != nil {
		return fmt.Errorf("DecodeChoice: extension field %q: %w", field.Name, err)
	}

	// Allocate pointer field if needed
	fv := rv.Field(fieldIdx)
	if fv.Kind() == reflect.Pointer {
		fv.Set(reflect.New(fv.Type().Elem()))
	}

	tmpDecoder := NewDecoder(openBytes, d.aligned)
	if err := tmpDecoder.decodeField(fv, tag); err != nil {
		return fmt.Errorf("DecodeChoice: extension field %q: %w", field.Name, err)
	}

	return nil
}

// decodeField decodes a single struct field value according to its type and PER tag.
// It resolves pointer indirection and dispatches to the appropriate type-specific decoder.
func (d *Decoder) decodeField(v reflect.Value, tag *Tag) error {
	// Resolve pointer indirection: allocate if nil, then work with the element
	if v.Kind() == reflect.Pointer {
		if v.IsNil() {
			v.Set(reflect.New(v.Type().Elem()))
		}
		v = v.Elem()
	}

	// Open type: the field is an interface whose concrete value is decoded
	// from an open type wrapper (length-determinant + inner encoding).
	// The concrete type must already be set on the interface by the caller
	// (typically generated code) before calling decode.
	if tag.Open {
		openBytes, err := d.DecodeOctetString(nil, nil, false)
		if err != nil {
			return fmt.Errorf("decodeField: open type: %w", err)
		}
		if v.Kind() == reflect.Interface {
			if v.IsNil() {
				return fmt.Errorf("decodeField: open type interface is nil (concrete type must be set before decoding)")
			}
			// Get the concrete value behind the interface
			concrete := v.Elem()
			if concrete.Kind() == reflect.Pointer {
				if concrete.IsNil() {
					concrete.Set(reflect.New(concrete.Type().Elem()))
				}
				concrete = concrete.Elem()
			}
			ttag := *tag
			ttag.Open = false
			tmpDecoder := NewDecoder(openBytes, d.aligned)
			return tmpDecoder.decodeField(concrete, &ttag)
		}
		// Non-interface open type: decode directly
		ttag := *tag
		ttag.Open = false
		tmpDecoder := NewDecoder(openBytes, d.aligned)
		return tmpDecoder.decodeField(v, &ttag)
	}

	fieldType := v.Type()

	// Handle well-known concrete types via type assertion first
	switch v.Addr().Interface().(type) {
	case *asn1.BitString:
		var lb, ub *uint64
		if tag.LB != nil {
			l := uint64(*tag.LB)
			lb = &l
		}
		if tag.UB != nil {
			u := uint64(*tag.UB)
			ub = &u
		}
		bs, err := d.DecodeBitString(lb, ub, tag.Ext)
		if err != nil {
			return err
		}
		v.Set(reflect.ValueOf(*bs))
		return nil

	case *NULL:
		return d.DecodeNull()

	case *Empty:
		return d.DecodeNull()
	}

	// Dispatch by reflect.Kind for primitive and generic types
	switch fieldType.Kind() {
	case reflect.Bool:
		val, err := d.DecodeBoolean()
		if err != nil {
			return err
		}
		v.SetBool(val)
		return nil

	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		val, err := d.DecodeInteger(tag.LB, tag.UB, tag.Ext)
		if err != nil {
			return err
		}
		v.SetInt(val)
		return nil

	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
		if tag.Enum != nil {
			val, err := d.DecodeEnumerated(*tag.Enum, tag.Ext)
			if err != nil {
				return err
			}
			v.SetUint(val)
			return nil
		}
		val, err := d.DecodeInteger(tag.LB, tag.UB, tag.Ext)
		if err != nil {
			return err
		}
		v.SetUint(uint64(val))
		return nil

	case reflect.Float32, reflect.Float64:
		val, err := d.DecodeReal()
		if err != nil {
			return err
		}
		v.SetFloat(val)
		return nil

	case reflect.String:
		var lb, ub *uint64
		if tag.LB != nil {
			l := uint64(*tag.LB)
			lb = &l
		}
		if tag.UB != nil {
			u := uint64(*tag.UB)
			ub = &u
		}
		val, err := d.DecodeString(lb, ub, tag.Ext)
		if err != nil {
			return err
		}
		v.SetString(val)
		return nil

	case reflect.Slice:
		// []byte (OCTET STRING)
		if fieldType.Elem().Kind() == reflect.Uint8 {
			var lb, ub *uint64
			if tag.LB != nil {
				l := uint64(*tag.LB)
				lb = &l
			}
			if tag.UB != nil {
				u := uint64(*tag.UB)
				ub = &u
			}
			data, err := d.DecodeOctetString(lb, ub, tag.Ext)
			if err != nil {
				return err
			}
			v.SetBytes(data)
			return nil
		}
		// SEQUENCE OF
		var lb, ub *uint64
		if tag.LB != nil {
			l := uint64(*tag.LB)
			lb = &l
		}
		if tag.UB != nil {
			u := uint64(*tag.UB)
			ub = &u
		}
		elemTag := tag.Elem
		if elemTag == nil {
			elemTag = &Tag{}
		}
		return d.DecodeSequenceOf(v.Addr().Interface(), lb, ub, tag.Ext, elemTag)

	case reflect.Array:
		// Fixed-size array: decode elements in place
		elemTag := tag.Elem
		if elemTag == nil {
			elemTag = &Tag{}
		}
		n := v.Len()
		for i := range n {
			if err := d.decodeField(v.Index(i), elemTag); err != nil {
				return fmt.Errorf("decodeField: array element %d: %w", i, err)
			}
		}
		return nil

	case reflect.Struct:
		meta, err := GetStructMeta(fieldType)
		if err != nil {
			return fmt.Errorf("decodeField: %s: %w", fieldType, err)
		}
		if meta.Choice {
			return d.DecodeChoice(v.Addr().Interface())
		}
		return d.DecodeSequence(v.Addr().Interface())

	case reflect.Interface:
		// Untagged interface field — resolve to concrete value and re-dispatch.
		// For open type interfaces, the tag.Open path above handles wrapping;
		// this branch handles the rare case of an interface field without the open tag.
		if v.IsNil() {
			return fmt.Errorf("decodeField: nil interface value")
		}
		concrete := v.Elem()
		if concrete.Kind() == reflect.Pointer {
			if concrete.IsNil() {
				concrete.Set(reflect.New(concrete.Type().Elem()))
			}
			concrete = concrete.Elem()
		}
		return d.decodeField(concrete, tag)

	default:
		return fmt.Errorf("decodeField: unsupported type %s", fieldType)
	}
}
