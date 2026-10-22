package per

import (
	"github.com/thebagchi/asn1c-go/lib/bitbuffer"
)

// CONSTRAINT_OPEN_TYPE is the size of an open type, X.691 11.2.2: an open type is an
// unconstrained OCTET STRING. One shared value keeps the codecs free of allocations.
var (
	CONSTRAINT_OPEN_TYPE = Unconstrained()
)

// OPEN_TYPE_EMPTY is the one zero octet that stands for a complete encoding of no bits, X.691
// 11.1.3, when the caller hands over no octets.
var (
	OPEN_TYPE_EMPTY = []byte{0}
)

// Nested returns a new Encoder of the same variant. The caller writes the inner value of an
// open type with it, and hands Bytes to EncodeOpenType, X.691 11.2. An inner encoding is
// complete and starts at an octet boundary, so it needs an encoder of its own.
//
// Revisions:
//   - 2026-10-19 14:31: initial creation
func (e *Encoder) Nested() *Encoder {
	return &Encoder{
		codec:   bitbuffer.CreateWriter(),
		aligned: e.aligned,
	}
}

// EncodeOpenType writes the complete encoding of an inner value as an open type, X.691 11.2.2:
// the length and the octets of an unconstrained OCTET STRING, so with fragments above 16K
// octets. An inner encoding of no octets becomes the one zero octet of 11.1.3.
//
// Revisions:
//   - 2026-10-19 14:31: initial creation
func (e *Encoder) EncodeOpenType(inner []byte) error {
	if len(inner) == 0 {
		inner = OPEN_TYPE_EMPTY
	}

	return e._EncodeOctetFragments(
		inner,
		CONSTRAINT_OPEN_TYPE,
	)
}

// DecodeOpenType reads an open type, X.691 11.2, and returns the octets of the inner complete
// encoding. The octets are a copy: in UPER they start at any bit of the input, so no view of
// the input can hold them. The caller decodes the inner value with a decoder of its own.
//
// Revisions:
//   - 2026-10-19 14:31: initial creation
func (d *Decoder) DecodeOpenType() ([]byte, error) {
	return d._DecodeOctetFragments(CONSTRAINT_OPEN_TYPE)
}

// SkipOpenTypes steps over count open types without a copy, X.691 11.2. Each carries its own
// length, so a decoder skips what it has no field for: the additions that a later version of
// the type declares, 19.7.
//
// Revisions:
//   - 2026-10-19 14:31: initial creation
func (d *Decoder) SkipOpenTypes(count uint64) error {
	for range count {
		if err := d._SkipOpenType(); err != nil {
			return err
		}
	}

	return nil
}

// _SkipOpenType reads the length of one open type, with its fragments, and steps over the
// octets that each length counts.
//
// Revisions:
//   - 2026-10-19 14:31: initial creation
func (d *Decoder) _SkipOpenType() error {
	if err := d._AlignForLength(CONSTRAINT_OPEN_TYPE); err != nil {
		return err
	}

	for {
		length, more, err := d.DecodeUnconstrainedLength()
		if err != nil {
			return err
		}

		if err := d._SkipOctets(length); err != nil {
			return err
		}

		if !more {
			return nil
		}
	}
}

// _SkipOctets steps over count octets. Aligned, the octets are a view of the input. Unaligned,
// they are read a word at a time and dropped, because a shifted copy would allocate.
//
// Revisions:
//   - 2026-10-19 14:31: initial creation
func (d *Decoder) _SkipOctets(count uint64) error {
	if count == 0 {
		return nil
	}

	if d.aligned {
		if err := d.codec.Advance(); err != nil {
			return err
		}

		_, err := d.codec.ReadView(int(count))

		return err
	}

	for ; count >= UINT64_BYTES; count -= UINT64_BYTES {
		if _, err := d.codec.Read(UINT64_BITS); err != nil {
			return err
		}
	}

	if count == 0 {
		return nil
	}

	_, err := d.codec.Read(uint8(count * BITS_PER_BYTE))

	return err
}
