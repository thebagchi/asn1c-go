package bitbuffer

import (
	"encoding/binary"
)

// _WritePeel writes a field that starts in the open byte and does not fit in it.
// The top free bits fill the open byte; its low bits are zero, so the bits before
// them stay. The rest bits start on a byte boundary and go out as whole bytes,
// most significant first, the way _WriteAligned writes them, but into room that
// _Grow makes, so no append copies the buffer.
//
// Revisions:
//   - 2026-10-21 09:45: initial creation (review P24)
func (c *Codec) _WritePeel(
	num uint8,
	value uint64,
	free uint8,
) {
	var (
		rest = num - free
		last = len(c.buff) - 1
	)

	c.buff[last] |= byte(value >> rest)

	var (
		nbytes = (int(rest) + BITS_PER_BYTE - 1) / BITS_PER_BYTE
		tmp    [UINT64_BYTES]byte
	)

	binary.BigEndian.PutUint64(
		tmp[:],
		value<<(UINT64_BITS-rest),
	)
	c._Grow(nbytes)
	copy(
		c.buff[len(c.buff)-nbytes:],
		tmp[:nbytes],
	)

	c.offset = rest % BITS_PER_BYTE
	if c.offset == 0 {
		c.offset = BITS_PER_BYTE
	}
}

// _ReadWide reads a field of more than PEEL_FIELD_MIN bits. Read sends it here with the
// one compare that it already makes against the widest field, so a short field pays
// nothing for this path. A field that starts inside a byte is that wide only when more
// than PEEL_READ_MIN bits remain after the open byte, so the open byte is taken whole
// and the rest is read on a byte boundary in one call.
//
// Revisions:
//   - 2026-10-21 10:00: initial creation (review P24)
//   - 2026-10-21 12:31: puts the offset back when the rest does not fit (review P25)
func (c *Codec) _ReadWide(num uint8) (uint64, error) {
	if num > UINT64_BITS {
		return 0, ErrInvalidBitCount
	}

	if len(c.buff) == 0 {
		return 0, ErrShortBuffer
	}

	if c.offset == 0 || c.offset == BITS_PER_BYTE {
		return c._ReadAligned(num)
	}

	var (
		left = BITS_PER_BYTE - c.offset
		head = uint64(c.buff[0]) & (uint64(1)<<left - 1)
	)

	c.offset = BITS_PER_BYTE

	tail, err := c._ReadAligned(num - left)
	if err != nil {
		c.offset = BITS_PER_BYTE - left

		return 0, err
	}

	return head<<(num-left) | tail, nil
}
