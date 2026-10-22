package per

import (
	"encoding/asn1"
	"errors"
	"fmt"
	"math/bits"
)

// ErrEmptyAdditions is what EncodeAdditions and DecodeAdditions report for an additions bitmap
// of no bits: X.691 19.8 note says that n cannot be zero.
var (
	ErrEmptyAdditions = errors.New("additions bitmap has no bits")
)

// _Word returns how many of the remaining bits of a bitmap travel in one call: all of them, or
// the widest field that the codec takes.
//
// Revisions:
//   - 2026-10-19 14:31: initial creation
func _Word(remaining uint64) uint64 {
	return min(
		remaining,
		UINT64_BITS,
	)
}

// _Scatter writes the low width bits of value into target at bit offset at, the most
// significant first. The offset is always a multiple of UINT64_BITS, so the destination is
// octet-aligned. The bits of the last octet after width are zero.
//
// Revisions:
//   - 2026-10-19 14:31: initial creation
func _Scatter(
	target []byte,
	at,
	width,
	value uint64,
) {
	index := at / BITS_PER_BYTE
	value <<= UINT64_BITS - width

	for written := uint64(0); written < width; written += BITS_PER_BYTE {
		target[index] = byte(value >> (UINT64_BITS - BITS_PER_BYTE))
		value <<= BITS_PER_BYTE
		index++
	}
}

// _Mine returns how many of the width bits of a word, read after read bits, fall in the
// known bits of the caller: all of them until the known bits end, then none.
//
// Revisions:
//   - 2026-10-19 14:31: initial creation
func _Mine(
	read,
	width,
	known uint64,
) uint64 {
	if read >= known {
		return 0
	}

	return min(
		width,
		known-read,
	)
}

// _CheckBitmap checks a bitmap of the caller and returns its length in bits. The octets must
// hold the bits. The text of an error has no value in it.
//
// Revisions:
//   - 2026-10-19 14:31: initial creation
func _CheckBitmap(value *asn1.BitString) (uint64, error) {
	if value == nil {
		return 0, fmt.Errorf(
			"bitmap: %w",
			ErrNilValue,
		)
	}

	if value.BitLength < 0 {
		return 0, fmt.Errorf(
			"bitmap length %d: %w",
			value.BitLength,
			ErrValueOutOfRange,
		)
	}

	count := uint64(value.BitLength)
	if uint64(len(value.Bytes))*BITS_PER_BYTE < count {
		return 0, fmt.Errorf(
			"%d bits in %d octets: %w",
			count,
			len(value.Bytes),
			ErrShortBitString,
		)
	}

	return count, nil
}

// EncodePreamble writes the presence bits of the OPTIONAL and DEFAULT components of a
// SEQUENCE or SET, X.691 19.2 and 21: one bit for each, in the order of the components, before
// any component. A SET passes its bits in the sorted order of 21. Below 64K bits the bitmap is
// a bit-field with no length. From 64K bits, 19.3 gives it the length and fragments of 11.9,
// those of an unconstrained BIT STRING. No bits write nothing. The caller packs the bits in
// its own array, so the call allocates nothing.
//
// Revisions:
//   - 2026-10-19 14:31: initial creation
func (e *Encoder) EncodePreamble(value *asn1.BitString) error {
	count, err := _CheckBitmap(value)
	if err != nil {
		return err
	}

	if count < MAX_CONSTRAINED_LENGTH {
		return e.WriteBits(
			value.Bytes,
			count,
		)
	}

	return e._EncodeBitFragments(
		value.Bytes,
		count,
		CONSTRAINT_OPEN_TYPE,
	)
}

// DecodePreamble reads the presence bits into the octets of the caller. The caller sets
// BitLength to the number of bits that its type has. Below 64K bits it reads them at once.
// From 64K bits it reads the fragments of 19.3, and refuses a total that is not BitLength.
//
// Revisions:
//   - 2026-10-19 14:31: initial creation
func (d *Decoder) DecodePreamble(value *asn1.BitString) error {
	count, err := _CheckBitmap(value)
	if err != nil {
		return err
	}

	if count < MAX_CONSTRAINED_LENGTH {
		return d._ReadBitmap(
			value.Bytes,
			count,
		)
	}

	got, err := d._DecodeBitFragments(CONSTRAINT_OPEN_TYPE)
	if err != nil {
		return err
	}

	if uint64(got.BitLength) != count {
		return fmt.Errorf(
			"%d bits in a preamble of %d: %w",
			got.BitLength,
			count,
			ErrLengthMismatch,
		)
	}

	copy(
		value.Bytes,
		got.Bytes,
	)

	return nil
}

// _ReadBitmap reads count bits into target, a word at a time.
//
// Revisions:
//   - 2026-10-19 14:31: initial creation
func (d *Decoder) _ReadBitmap(
	target []byte,
	count uint64,
) error {
	for read := uint64(0); read < count; {
		var (
			width = _Word(count - read)

			value, err = d.codec.Read(uint8(width))
		)
		if err != nil {
			return err
		}

		_Scatter(
			target,
			read,
			width,
			value,
		)

		read += width
	}

	return nil
}

// EncodeAdditions writes the bitmap of the extension additions, X.691 19.7 and 11.9.3.4: for n
// additions up to 64 a 0 bit and n-1 in six bits, then the bits. For more, a 1 bit and n as an
// unconstrained length, then the bits, with the octet alignment and the fragments of 11.9.3.5
// to 11.9.3.8, which are those of a BIT STRING. 19.8 gives no encoding for n of zero, and 19.6
// ends the encoding when no addition is present, so the call refuses an empty bitmap with
// ErrEmptyAdditions. The call checks its input before it writes, so an error leaves the
// encoder as it was.
//
// Revisions:
//   - 2026-10-19 14:55: initial creation
//   - 2026-10-19 14:55: n above 64 uses the fragments of 11.9.3.8, and no bit is written
//     before the checks (review P7-7)
func (e *Encoder) EncodeAdditions(value *asn1.BitString) error {
	count, err := _CheckBitmap(value)
	if err != nil {
		return err
	}

	if count == 0 {
		return fmt.Errorf(
			"additions bitmap of no bits: %w",
			ErrEmptyAdditions,
		)
	}

	if count > NORMALLY_SMALL_LENGTH_MAX {
		if err := e.codec.Write(
			1,
			1,
		); err != nil {
			return err
		}

		return e._EncodeBitFragments(
			value.Bytes,
			count,
			CONSTRAINT_OPEN_TYPE,
		)
	}

	if _, err := e.EncodeNormallySmallLength(count); err != nil {
		return err
	}

	return e.WriteBits(
		value.Bytes,
		count,
	)
}

// DecodeAdditions reads the bitmap of the extension additions, X.691 19.7 and 11.9.3.4, into
// the known bits of the caller, and returns how many additions beyond them are present. A
// sender of a later version declares more additions than the caller knows. The caller then
// reads the open types of its own, and passes the returned number to SkipOpenTypes. A sender
// of an earlier version declares fewer, and the bits that it does not send are zero. A length
// of zero is ErrEmptyAdditions, as 19.8 gives no such encoding.
//
// Revisions:
//   - 2026-10-19 14:55: initial creation
//   - 2026-10-19 14:55: n above 64 reads the fragments of 11.9.3.8 (review P7-7)
func (d *Decoder) DecodeAdditions(value *asn1.BitString) (uint64, error) {
	known, err := _CheckBitmap(value)
	if err != nil {
		return 0, err
	}

	large, err := d.codec.Read(1)
	if err != nil {
		return 0, err
	}

	clear(value.Bytes[:(known+BITS_PER_BYTE-1)/BITS_PER_BYTE])

	if large == 0 {
		count, err := d.codec.Read(NORMALLY_SMALL_BITS)
		if err != nil {
			return 0, err
		}

		return d._ReadAdditionBits(
			value.Bytes,
			count+1,
			known,
		)
	}

	return d._DecodeLargeAdditions(
		value.Bytes,
		known,
	)
}

// _DecodeLargeAdditions reads the bitmap of more than 64 additions, a BIT STRING with an
// unconstrained length, and splits it as _ReadAdditionBits does.
//
// Revisions:
//   - 2026-10-19 14:55: initial creation (review P7-7)
func (d *Decoder) _DecodeLargeAdditions(
	target []byte,
	known uint64,
) (uint64, error) {
	got, err := d._DecodeBitFragments(CONSTRAINT_OPEN_TYPE)
	if err != nil {
		return 0, err
	}

	count := uint64(got.BitLength)
	if count == 0 {
		return 0, fmt.Errorf(
			"additions bitmap of no bits: %w",
			ErrEmptyAdditions,
		)
	}

	unknown := uint64(0)

	for read := uint64(0); read < count; {
		var (
			width = _Word(count - read)
			value = _Take(
				got.Bytes,
				read,
				width,
			)
			mine = _Mine(
				read,
				width,
				known,
			)
		)

		if mine > 0 {
			_Scatter(
				target,
				read,
				mine,
				value>>(width-mine),
			)
		}

		unknown += uint64(bits.OnesCount64(value & (1<<(width-mine) - 1)))
		read += width
	}

	return unknown, nil
}

// _Take returns width bits of source from bit offset at, in the low bits of the result. The
// offset is a multiple of UINT64_BITS, so the bits start at an octet. The octets that the
// bits need are in source.
//
// Revisions:
//   - 2026-10-19 14:55: initial creation (review P7-7)
func _Take(
	source []byte,
	at,
	width uint64,
) uint64 {
	var (
		value = uint64(0)
		index = at / BITS_PER_BYTE
	)

	for taken := uint64(0); taken < width; taken += BITS_PER_BYTE {
		value = value<<BITS_PER_BYTE | uint64(source[index])
		index++
	}

	used := (width + BITS_PER_BYTE - 1) / BITS_PER_BYTE * BITS_PER_BYTE

	return value >> (used - width)
}

// _ReadAdditionBits reads count bits. The first known bits go into target, and the present
// bits after them are counted.
//
// Revisions:
//   - 2026-10-19 14:31: initial creation
func (d *Decoder) _ReadAdditionBits(
	target []byte,
	count,
	known uint64,
) (uint64, error) {
	unknown := uint64(0)

	for read := uint64(0); read < count; {
		var (
			width = _Word(count - read)

			value, err = d.codec.Read(uint8(width))
		)
		if err != nil {
			return 0, err
		}

		mine := _Mine(
			read,
			width,
			known,
		)
		if mine > 0 {
			_Scatter(
				target,
				read,
				mine,
				value>>(width-mine),
			)
		}

		rest := value & (1<<(width-mine) - 1)
		unknown += uint64(bits.OnesCount64(rest))
		read += width
	}

	return unknown, nil
}

// OptionalBitmap returns the words of a root preamble of count bits, X.691 19.2.
//
// The codec writes and reads at most UINT64_BITS bits in one call, so each word
// is one such call. The first optional is the most significant bit of words[0].
// A count of zero returns a nil slice and writes nothing. The caller sets the
// bits, then passes the slice to WriteOptional.
//
// Revisions:
//   - 2026-10-20 13:41: initial creation
func OptionalBitmap(count uint64) []uint64 {
	words := _BitmapWords(count)

	return words
}

// ExtensionBitmap returns the words of an additions bitmap of count bits, X.691 19.7.
//
// The bit order matches OptionalBitmap. The length determinant is not one of the
// words: WriteExtension writes it. A count of zero returns a nil slice, and
// WriteExtension refuses it, because 19.8 gives that bitmap no encoding.
//
// Revisions:
//   - 2026-10-20 13:41: initial creation
func ExtensionBitmap(count uint64) []uint64 {
	words := _BitmapWords(count)

	return words
}

// BitmapSet sets one bit in a bitmap from OptionalBitmap or ExtensionBitmap.
// Bit zero is the first component, the top bit of words[0] (X.691 19.2, 19.7).
//
// Revisions:
//   - 2026-10-20 13:41: initial creation, as BitmapPlace
//   - 2026-10-20 14:09: sets the bit itself, so it returns no word and mask pair of one
//     type (review P20)
func BitmapSet(
	words []uint64,
	bit uint64,
) {
	words[bit/UINT64_BITS] |= _BitmapMask(bit)
}

// BitmapHas reports one bit of a bitmap from OptionalBitmap or ExtensionBitmap.
//
// Revisions:
//   - 2026-10-20 14:09: initial creation (review P20)
func BitmapHas(
	words []uint64,
	bit uint64,
) bool {
	return words[bit/UINT64_BITS]&_BitmapMask(bit) != 0
}

// WriteOptional writes a root preamble from the words OptionalBitmap returned.
//
// A count below 64 is one field of that width. A count above 64, and still
// below 64K, is one field of 64 per full word, then one field of the remainder
// when the count is not a multiple of 64. That remainder is below 64. From 64K
// bits the preamble has the fragments of 19.3. A count of zero writes nothing.
//
// Revisions:
//   - 2026-10-20 13:41: initial creation
//   - 2026-10-20 13:49: a count below 64 is one partial word, and a count above
//     64 is full words plus a remainder below 64
//   - 2026-10-20 14:09: from 64K bits writes the fragments from the words, with no octet
//     copy (review P20); grows the buffer once for the whole preamble
func (e *Encoder) WriteOptional(
	words []uint64,
	count uint64,
) error {
	if count == 0 {
		return nil
	}

	if err := _BitmapFits(
		words,
		count,
	); err != nil {
		return err
	}

	if count < MAX_CONSTRAINED_LENGTH {
		e.codec.Grow(_BitmapOctets(count))

		return e._WriteBitmap(
			words,
			count,
		)
	}

	return e._EncodeWordFragments(
		words,
		count,
	)
}

// ReadOptional reads a root preamble into words. count is the number of bits
// the caller's type has, and words came from OptionalBitmap.
//
// Revisions:
//   - 2026-10-20 13:41: initial creation
//   - 2026-10-21 17:25: from 64K bits reads the fragments into the words, with no octet
//     copy (review P29-2)
func (d *Decoder) ReadOptional(
	words []uint64,
	count uint64,
) error {
	if count == 0 {
		return nil
	}

	if err := _BitmapFits(
		words,
		count,
	); err != nil {
		return err
	}

	clear(words)

	if count < MAX_CONSTRAINED_LENGTH {
		return d._ReadWords(
			words,
			count,
		)
	}

	got, err := d._DecodeWordFragments(
		words,
		count,
	)
	if err != nil {
		return err
	}

	if got.total != count {
		return fmt.Errorf(
			"%d bits in a preamble of %d: %w",
			got.total,
			count,
			ErrLengthMismatch,
		)
	}

	return nil
}

// WriteExtension writes an additions bitmap from the words ExtensionBitmap
// returned, including the length determinant of 19.7.
//
// Up to 64 bits the length is normally small. A shorter count is one field of
// that width. Above 64, and below one 16K fragment, the length is the large
// form and the words go to the codec one call at a time, so a remainder below
// 64 is its own field. From 16K bits the bits take the fragments of 11.9.3.8.
// A count of zero is ErrEmptyAdditions.
//
// Revisions:
//   - 2026-10-20 13:41: initial creation
//   - 2026-10-20 13:49: a count below 64 is one partial word, and a count above
//     64 is full words plus a remainder below 64
//   - 2026-10-20 14:09: above 64 bits writes the length and the fragments from the words,
//     with no octet copy (review P20)
func (e *Encoder) WriteExtension(
	words []uint64,
	count uint64,
) error {
	if count == 0 {
		return fmt.Errorf(
			"additions bitmap of no bits: %w",
			ErrEmptyAdditions,
		)
	}

	if err := _BitmapFits(
		words,
		count,
	); err != nil {
		return err
	}

	if count > NORMALLY_SMALL_LENGTH_MAX {
		if err := e.codec.Write(
			1,
			1,
		); err != nil {
			return err
		}

		return e._EncodeWordFragments(
			words,
			count,
		)
	}

	if _, err := e.EncodeNormallySmallLength(count); err != nil {
		return err
	}

	return e._WriteBitmap(
		words,
		count,
	)
}

// ReadExtension reads an additions bitmap into the known bits of words and
// returns how many additions beyond them are present. count is how many bits
// the caller knows. The rules match DecodeAdditions.
//
// Revisions:
//   - 2026-10-20 13:41: initial creation
func (d *Decoder) ReadExtension(
	words []uint64,
	count uint64,
) (uint64, error) {
	if err := _BitmapFits(
		words,
		count,
	); err != nil {
		return 0, err
	}

	large, err := d.codec.Read(1)
	if err != nil {
		return 0, err
	}

	clear(words)

	if large == 0 {
		got, err := d.codec.Read(NORMALLY_SMALL_BITS)
		if err != nil {
			return 0, err
		}

		return d._ReadExtensionWords(
			words,
			0,
			got+1,
			count,
		)
	}

	return d._ReadLargeExtension(
		words,
		count,
	)
}

// _BitmapWords returns the words a bitmap of count bits needs, or nil when
// there are none.
//
// Revisions:
//   - 2026-10-20 13:41: initial creation
func _BitmapWords(count uint64) []uint64 {
	if count == 0 {
		return nil
	}

	return make(
		[]uint64,
		(count+UINT64_BITS-1)/UINT64_BITS,
	)
}

// _BitmapFits reports a slice too short for count bits.
//
// Revisions:
//   - 2026-10-20 13:41: initial creation
func _BitmapFits(
	words []uint64,
	count uint64,
) error {
	if count == 0 {
		return nil
	}

	need := (count + UINT64_BITS - 1) / UINT64_BITS
	if uint64(len(words)) < need {
		return fmt.Errorf(
			"%d bits in %d words: %w",
			count,
			len(words),
			ErrShortBitString,
		)
	}

	return nil
}

// _WriteBitmap writes count bits of words, one codec call per word.
//
// A count below 64 is one field of that width. A count above 64 is one field
// of 64 per full word, then one field of the remainder when the count is not
// a multiple of 64. That remainder is below 64.
//
// Revisions:
//   - 2026-10-20 13:41: initial creation
//   - 2026-10-20 13:49: a count below 64 is one partial word, and a count above
//     64 is full words plus a remainder below 64
func (e *Encoder) _WriteBitmap(
	words []uint64,
	count uint64,
) error {
	var (
		full = count / UINT64_BITS
		rest = count % UINT64_BITS
	)

	for index := uint64(0); index < full; index++ {
		if err := e.codec.Write(
			UINT64_BITS,
			words[index],
		); err != nil {
			return err
		}
	}

	if rest == 0 {
		return nil
	}

	return e.codec.Write(
		uint8(rest),
		words[full]>>(UINT64_BITS-rest),
	)
}

// _EncodeWordFragments writes count bits of words behind an unconstrained length,
// X.691 11.9.3.6 to 11.9.3.8. A preamble of 64K bits or more (19.3) and an
// additions bitmap above 64 bits (19.8, 11.9.3.4) take this form. It is the loop
// of _EncodeBitFragments without the octet copy: a fragment holds a multiple of
// 16K bits, so every fragment starts on a word, and _WriteBitmap writes it. The
// buffer grows once for the whole bitmap, as one WriteBytes of the copy did.
//
// Revisions:
//   - 2026-10-20 14:09: initial creation (review P20)
func (e *Encoder) _EncodeWordFragments(
	words []uint64,
	count uint64,
) error {
	e.codec.Grow(_BitmapOctets(count))

	if err := e._AlignForLength(CONSTRAINT_OPEN_TYPE); err != nil {
		return err
	}

	for offset := uint64(0); ; {
		pending, err := e.EncodeLengthDeterminant(
			count-offset,
			CONSTRAINT_OPEN_TYPE,
		)
		if err != nil {
			return err
		}

		length := count - offset - pending
		if e.aligned && length > 0 {
			if err := e.codec.Align(); err != nil {
				return err
			}
		}

		if err := e._WriteBitmap(
			words[offset/UINT64_BITS:],
			length,
		); err != nil {
			return err
		}

		offset += length
		if pending == 0 {
			return e._CloseFragments(
				count,
				offset,
				CONSTRAINT_OPEN_TYPE,
			)
		}
	}
}

// _BitmapOctets returns the octets a bitmap of count bits can take on the wire:
// its bits, one length octet for each 16K fragment, and the slack of a length and
// a pad. Growing the buffer once by this much replaces the doublings of one
// write per word.
//
// Revisions:
//   - 2026-10-20 14:11: initial creation (review P20)
func _BitmapOctets(count uint64) int {
	return int((count+BITS_PER_BYTE-1)/BITS_PER_BYTE + count/FRAGMENT_SIZE + GROW_SLACK)
}

// _BitmapMask returns the mask of one bit inside its word. Bit zero of a word is
// its top bit.
//
// Revisions:
//   - 2026-10-20 14:09: initial creation (review P20)
func _BitmapMask(bit uint64) uint64 {
	return uint64(1) << (UINT64_BITS - 1 - bit%UINT64_BITS)
}

// _ReadWords reads count bits into words, one codec call per word.
//
// A count below 64 is one field of that width. A count above 64 is one field
// of 64 per full word, then one field of the remainder when the count is not
// a multiple of 64. That remainder is below 64. The bits of a word sit at the
// top of the word.
//
// Revisions:
//   - 2026-10-20 13:41: initial creation
//   - 2026-10-20 13:49: a count below 64 is one partial word, and a count above
//     64 is full words plus a remainder below 64
func (d *Decoder) _ReadWords(
	words []uint64,
	count uint64,
) error {
	var (
		full = count / UINT64_BITS
		rest = count % UINT64_BITS
	)

	for index := uint64(0); index < full; index++ {
		value, err := d.codec.Read(UINT64_BITS)
		if err != nil {
			return err
		}

		words[index] = value
	}

	if rest == 0 {
		return nil
	}

	value, err := d.codec.Read(uint8(rest))
	if err != nil {
		return err
	}

	words[full] = value << (UINT64_BITS - rest)

	return nil
}

// _ReadExtensionWords reads count bits of a bitmap that start at bit start. The bits
// before bit known go into words, and the present bits after it are counted. start is
// a multiple of 64, so each read of 64 bits fills one word.
//
// Revisions:
//   - 2026-10-20 13:41: initial creation
//   - 2026-10-21 17:25: takes the bit the read starts at, so one fragment of a long
//     bitmap goes to its place in the words (review P29-2)
func (d *Decoder) _ReadExtensionWords(
	words []uint64,
	start,
	count,
	known uint64,
) (uint64, error) {
	var (
		unknown uint64
		end     = start + count
	)

	for read := start; read < end; {
		var (
			width = _Word(end - read)

			value, err = d.codec.Read(uint8(width))
		)
		if err != nil {
			return 0, err
		}

		mine := _Mine(
			read,
			width,
			known,
		)
		if mine > 0 {
			shift := (UINT64_BITS - mine) & (UINT64_BITS - 1)
			words[read/UINT64_BITS] |= (value >> (width - mine)) << shift
		}

		unknown += uint64(bits.OnesCount64(value & _LowMask(width-mine)))
		read += width
	}

	return unknown, nil
}

// _ReadLargeExtension reads more than 64 additions and splits them as
// _ReadExtensionWords does.
//
// Revisions:
//   - 2026-10-20 13:41: initial creation
//   - 2026-10-21 17:25: reads the fragments into the words and counts the rest as it
//     reads, with no octet copy (review P29-2)
func (d *Decoder) _ReadLargeExtension(
	words []uint64,
	known uint64,
) (uint64, error) {
	got, err := d._DecodeWordFragments(
		words,
		known,
	)
	if err != nil {
		return 0, err
	}

	if got.total == 0 {
		return 0, fmt.Errorf(
			"additions bitmap of no bits: %w",
			ErrEmptyAdditions,
		)
	}

	return got.unknown, nil
}

// _Tally is what a bitmap behind a length holds: its bits, and the present bits after
// the bits the caller knows.
type _Tally struct {
	total   uint64
	unknown uint64
}

// _DecodeWordFragments reads a bitmap behind an unconstrained length, X.691 11.9.3.6 to
// 11.9.3.8, into words: the bits before bit known go into words, and the present bits
// after it are counted. It is the loop of _DecodeBitFragments without the octet slice. A
// fragment before the last holds a multiple of 16K bits, so every fragment starts on a
// word, and _ReadExtensionWords reads it into its place. In APER the length starts on an
// octet and is whole octets, and a fragment before the last is whole octets, so the bits
// after a length are already on an octet: there is no pad to skip.
//
// Revisions:
//   - 2026-10-21 17:25: initial creation (review P29-2)
func (d *Decoder) _DecodeWordFragments(
	words []uint64,
	known uint64,
) (*_Tally, error) {
	if err := d._AlignForLength(CONSTRAINT_OPEN_TYPE); err != nil {
		return nil, err
	}

	tally := &_Tally{}

	for {
		length, more, err := d.DecodeLengthDeterminant(CONSTRAINT_OPEN_TYPE)
		if err != nil {
			return nil, err
		}

		unknown, err := d._ReadExtensionWords(
			words,
			tally.total,
			length,
			known,
		)
		if err != nil {
			return nil, err
		}

		tally.total += length
		tally.unknown += unknown

		if !more {
			return tally, nil
		}
	}
}

// _LowMask returns the low width bits set, or every bit when width is 64.
//
// Revisions:
//   - 2026-10-20 13:41: initial creation
func _LowMask(width uint64) uint64 {
	if width >= UINT64_BITS {
		return ^uint64(0)
	}

	return (uint64(1) << width) - 1
}
