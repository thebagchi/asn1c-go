// Package per implements ASN.1 Packed Encoding Rules, ITU-T X.691 (02/2021),
// in both the ALIGNED and UNALIGNED variants of BASIC-PER.
//
// Encoder and Decoder carry the variant they were built for, so a caller picks
// it once at construction and no call below repeats it. Constraint carries the
// PER-visible bounds and extension marker of the type being encoded, which X.691
// treats as one thing and which therefore travel together here.
//
// The clause numbers quoted throughout refer to X.691 unless a comment says
// X.690; the clause text itself is in X691.md beside this file rather than
// inline, so the code reads as code and the specification reads as prose.
package per

import (
	"encoding/asn1"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"reflect"
	"unsafe"
)

// Sentinel errors, so a caller matches with errors.Is rather than on the text.
var (
	ErrOddHexLength   = errors.New("hex string length must be even")
	ErrInvalidHex     = errors.New("invalid hex character")
	ErrInvalidBinary  = errors.New("invalid binary character")
	ErrShortBitString = errors.New("bit string is shorter than its bit length")
)

// Reflect types resolved once, so dispatch compares a type rather than boxing a
// value with Interface. Boxing allocates for any non-pointer field, and panics
// outright for a field reached through an unexported one.
var (
	TYPE_EMPTY     = reflect.TypeFor[Empty]()
	TYPE_NULL      = reflect.TypeFor[NULL]()
	TYPE_BITSTRING = reflect.TypeFor[asn1.BitString]()
	TYPE_OID       = reflect.TypeFor[asn1.ObjectIdentifier]()

	// TYPE_MARKER is the anonymous struct{} an extension marker field is
	// declared as. It is deliberately not TYPE_EMPTY: Empty is a named type, and
	// a named type is not the same reflect.Type as the anonymous one a caller
	// writes in `_ struct{}`.
	TYPE_MARKER = reflect.TypeFor[struct{}]()
)

// EmptyType is the reflect.Type of struct{}, which marks an extension marker
// field. It keeps its original name because struct tags document it.
var (
	EmptyType = TYPE_MARKER
)

// Empty is a zero-width placeholder. As a field tagged per:"ext" it marks where
// a SEQUENCE or CHOICE extension marker falls.
type Empty struct {
	// EMPTY
}

// NULL is the ASN.1 NULL type. X.691 clause 18 gives it no encoding at all, so
// the type carries no value.
type NULL struct {
	// EMPTY
}

// NewNULL returns a NULL.
//
// Revisions:
//   - 2026-03-02 22:36: initial creation
func NewNULL() *NULL {
	return new(NULL)
}

// NewEmpty returns an Empty.
//
// Revisions:
//   - 2026-03-02 22:36: initial creation
func NewEmpty() *Empty {
	return new(Empty)
}

// HEX_PAIR is how many hexadecimal characters one byte takes.
const (
	HEX_PAIR = 2
)

// BytesToHex renders data as lowercase hexadecimal.
//
// The assembly kernel takes whole blocks and the Go kernel the tail, into one
// buffer that becomes the result without a copy.
//
// Revisions:
//   - 2026-09-22 06:43: initial creation, byte-parallel
//   - 2026-09-22 09:12: hands the work to encoding/hex. The block form assembled
//     eight nibbles into a word and stored it once, which is only worth doing
//     when the per-byte work is arithmetic; here it is a table lookup, and the
//     block form just adds the assembly and disassembly around the same eight
//     lookups. Measured on 4 KiB: no significant difference for encoding, and a
//     2.2x loss for decoding, against the standard library
//   - 2026-09-23 08:40: a table lookup per byte is exactly what a 32-lane
//     shuffle does in one instruction; the vector kernel takes whole blocks
//     and encoding/hex the tail
//   - 2026-09-24 01:40: the kernel chain ends with the Go kernel, which is
//     encoding/hex, so it renders every byte
//   - 2026-09-24 02:00: finishes with the Go kernel here; kernel.go says why
func BytesToHex(data []byte) string {
	var (
		text = make([]byte, hex.EncodedLen(len(data)))
		done = _EncodeHex(text, data)
	)

	_HexEncodeGo(text[done*HEX_PAIR:], data[done:])

	return _BytesString(text)
}

// HexToBytes decodes hexadecimal text, in either letter case, into bytes.
//
// The assembly kernel takes whole blocks and stops at the first block holding
// anything that is not a hexadecimal digit; encoding/hex takes it from there -
// it is the Go kernel's body, called directly because it also says why it
// stopped - so the error, the first bad character or an odd length only when
// every character was good, is the one it always reported.
//
// Revisions:
//   - 2026-09-22 06:43: initial creation, byte-parallel
//   - 2026-09-22 09:12: hands the work to encoding/hex, which is faster than
//     either block form measured: 4.7us against 6.1us unrolled and 10.5us as
//     written, on 4 KiB. See BytesToHex for why
//   - 2026-09-23 08:40: the vector kernel takes whole blocks and encoding/hex
//     the remainder, errors included
func HexToBytes(text string) ([]byte, error) {
	var (
		src  = _StringBytes(text)
		data = make([]byte, hex.DecodedLen(len(src)))
		done = _DecodeHex(data, src)
	)

	count, err := hex.Decode(data[done/HEX_PAIR:], src[done:])
	if err == nil {
		return data[:done/HEX_PAIR+count], nil
	}

	if errors.Is(err, hex.ErrLength) {
		return nil, ErrOddHexLength
	}

	var invalid hex.InvalidByteError
	if errors.As(err, &invalid) {
		return nil, fmt.Errorf("%q: %w", rune(invalid), ErrInvalidHex)
	}

	return nil, err
}

// BitStringToBinary renders a bit string as the characters '0' and '1', leading
// bit first.
//
// Eight characters are produced per byte from one multiply: replicating the byte
// into all eight lanes and masking each lane to a different bit leaves one bit
// per lane, which then only needs normalising and biasing to ASCII.
//
// Revisions:
//   - 2026-03-02 22:36: initial creation
//   - 2026-09-22 06:43: builds the result in one allocation. It appended one
//     character at a time to a string, which copies the whole string per bit and
//     cost 1.5ms and 4092 allocations for a 4093-bit value, against 1.9us and two
//   - 2026-09-23 08:40: the vector kernel takes whole blocks of whole bytes and
//     the word loop the rest, and the buffer becomes the result without a copy
//   - 2026-09-24 02:00: the word loop is the Go kernel, called for the rest
func BitStringToBinary(value *asn1.BitString) string {
	if value == nil || value.BitLength <= 0 {
		return ""
	}

	length := value.BitLength
	if limit := len(value.Bytes) * BITS_PER_BYTE; length > limit {
		length = limit
	}

	// Rounded up to a whole byte so the final lane store stays in bounds; the
	// result is cut back to length before it is returned.
	var (
		bytes = (length + BITS_PER_BYTE - 1) / BITS_PER_BYTE
		text  = make([]byte, bytes*BITS_PER_BYTE)
		done  = _EncodeBinary(text, value.Bytes[:length/BITS_PER_BYTE])
	)

	_BinaryEncodeGo(text[done*BITS_PER_BYTE:], value.Bytes[done:bytes])

	return _BytesString(text[:length])
}

// BitStringFromBinary parses characters '0' and '1', leading bit first, into a
// bit string.
//
// Eight characters are validated and gathered per iteration. Subtracting '0'
// from every lane at once leaves 0 or 1 in a valid lane and sets a high bit in
// any other, so one test covers all eight; the multiply that follows sums the
// eight lanes into the byte they denote.
//
// The kernels take whole blocks - eight characters, for the Go one - and stop
// at the first block holding anything that is not '0' or '1', so a whole word
// left over is the word holding the bad character, and the offset reported -
// its start - is the one this always reported.
//
// Revisions:
//   - 2026-03-02 22:36: initial creation
//   - 2026-09-22 06:43: validates and gathers eight characters at a time, which
//     is 12 times faster on a 4093-bit value than the per-character loop
//   - 2026-09-23 08:40: the vector kernel takes whole blocks and the word loop
//     the remainder, errors included
//   - 2026-09-24 02:00: the word loop is the Go kernel, called for the rest; a
//     whole word it leaves is the bad one
func BitStringFromBinary(text string) (*asn1.BitString, error) {
	if text == "" {
		return &asn1.BitString{}, nil
	}

	var (
		src  = _StringBytes(text)
		data = make([]byte, (len(src)+BITS_PER_BYTE-1)/BITS_PER_BYTE)
		pos  = _DecodeBinary(data, src)
	)

	pos += _BinaryDecodeGo(data[pos/BITS_PER_BYTE:], src[pos:])

	if pos+BITS_PER_BYTE <= len(src) {
		return nil, fmt.Errorf("at offset %d: %w", pos, ErrInvalidBinary)
	}

	if pos < len(src) {
		// The last partial byte is padded with '0', which is both a valid
		// character and the zero bit PER pads a bit string with. Copying the
		// constant beats filling it: Go turns a zero fill into a memclr but
		// leaves a non-zero one as a loop.
		tail := ASCII_ZEROS
		copy(tail[:], src[pos:])

		bits, ok := _BinaryWord(binary.BigEndian.Uint64(tail[:]))
		if !ok {
			return nil, fmt.Errorf("at offset %d: %w", pos, ErrInvalidBinary)
		}

		data[pos/BITS_PER_BYTE] = bits
	}

	return &asn1.BitString{
		Bytes:     data,
		BitLength: len(src),
	}, nil
}

// _StringBytes returns a read-only view of a string's bytes.
//
// Nothing that receives the result writes through it or keeps it past the call,
// so the copy a conversion would make is avoided.
//
// This is the only shape of unsafe this package uses, and it is the only one
// that is safe to use here: it addresses bytes, so it means the same thing on
// either byte order. Reading a multi-byte value through an unsafe pointer does
// not - `*(*uint64)(p)` is whatever the machine's order makes it - so every
// multi-byte access below names binary.BigEndian or binary.LittleEndian and
// lets the compiler emit the swap, or not, as the target needs.
//
// Revisions:
//   - 2026-09-22 06:43: initial creation
func _StringBytes(value string) []byte {
	if value == "" {
		return nil
	}

	return unsafe.Slice(unsafe.StringData(value), len(value))
}

// _BytesString returns text as a string without copying it.
//
// It is the mirror of _StringBytes and carries the mirror of its condition:
// the caller must never write to text again, because the string now shares
// its bytes and a string's bytes are immutable by contract. Every caller here
// builds text, hands it over, and drops it. Like _StringBytes it addresses
// bytes only, so byte order does not come into it.
//
// Revisions:
//   - 2026-09-23 07:40: initial creation
func _BytesString(text []byte) string {
	if len(text) == 0 {
		return ""
	}

	return unsafe.String(unsafe.SliceData(text), len(text))
}

// _BinaryWord converts eight characters, packed one per lane with the leading
// character in the most significant, to the byte they denote. ok is false if any
// lane holds something that is neither '0' nor '1'.
//
// Revisions:
//   - 2026-09-22 06:43: initial creation
func _BinaryWord(lanes uint64) (byte, bool) {
	bits := lanes ^ ASCII_ZERO_LANES
	if bits&^LOW_BIT_LANES != 0 {
		return 0, false
	}

	return byte((bits * BIT_GATHER) >> BIT_GATHER_SHIFT), true
}

// _SpreadBits spreads the eight bits of value into the eight bytes of the
// result, most significant bit first, each byte holding 0 or 1.
//
// Replicating the byte into every lane and masking each lane to a different bit
// leaves one bit somewhere in each lane; adding 0x7f to a lane carries into its
// high bit exactly when the lane was non-zero, which normalises all eight at
// once.
//
// Revisions:
//   - 2026-09-22 06:43: initial creation
func _SpreadBits(value byte) uint64 {
	lanes := (uint64(value) * LOW_BIT_LANES) & BIT_SPREAD_PICK

	return ((lanes + BIT_SPREAD_BIAS) >> BIT_SPREAD_SHIFT) & LOW_BIT_LANES
}
