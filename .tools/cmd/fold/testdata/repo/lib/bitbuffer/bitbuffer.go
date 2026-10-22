// Package bitbuffer provides bit-level I/O for ASN.1 PER (Packed Encoding Rules).
//
// Codec is a bit stream with MSB-first ordering: the most significant bit of a
// value is written first, which is what X.691 clause 11.3.2 means by the leading
// bit of a field. Fields are 1 to 64 bits wide and need not be byte-aligned, so
// a Codec tracks a bit offset within the byte it is in rather than a byte index.
//
// Two representations of a byte boundary exist, and the difference is
// load-bearing. An offset of zero means no bit of the current byte has been used;
// an offset of BITS_PER_BYTE means every bit has been used but the buffer has not
// yet advanced past it. Deferring that advance keeps Align and Advance O(1) and
// lets a read that ends on a boundary avoid touching the slice header at all.
//
// A Codec is not safe for concurrent use. Callers own higher-level ASN.1
// semantics: this package validates bit counts and buffer length, and nothing
// about the values it carries.
package bitbuffer

import (
	"encoding/binary"
	"errors"
	"fmt"
	"slices"
)

// ENABLE_TRACE turns on the per-call trace written by _Trace. It is a var rather
// than a const so a caller can switch it on around a failing decode without
// rebuilding, and every call site is guarded by it so the cost when it is off is
// one predictable branch.
var (
	ENABLE_TRACE = false
)

// Sentinel errors, so a caller matches with errors.Is rather than on the text.
var (
	ErrInvalidBitCount = errors.New("bit count must be between 1 and 64")
	ErrShortBuffer     = errors.New("insufficient data")
	ErrNegativeCount   = errors.New("negative byte count")
)

// Codec is a bit stream being written or read.
//
// buff holds the bytes; offset is how many bits of the byte the stream is
// currently in have been used, from 0 to BITS_PER_BYTE inclusive, with
// BITS_PER_BYTE meaning "full, advance before using another"; written and read
// count bits rather than bytes, so a caller can tell a 3-bit message from a
// 5-bit one. Both counters are uint64 and cannot overflow on any real message.
type Codec struct {
	buff    []byte
	offset  uint8
	written uint64
	read    uint64
}

// CreateWriter returns a Codec that appends to a buffer of its own.
//
// The capacity reserved up front covers the preamble and first fields of a
// typical message, so the common case never reallocates.
//
// Revisions:
//   - 2026-01-20 23:00: initial creation
//   - 2026-09-22 06:43: reserves INITIAL_CAPACITY, a constant, in place of the
//     package-level InitialBufferSize variable a caller could change underneath
//     a Codec that had already allocated
func CreateWriter() *Codec {
	return &Codec{
		buff: make([]byte, 0, INITIAL_CAPACITY),
	}
}

// CreateReader returns a Codec that reads data from its first bit.
//
// data is not copied, so a caller must not modify it while the Codec reads.
//
// Revisions:
//   - 2026-01-20 23:00: initial creation
func CreateReader(data []byte) *Codec {
	return &Codec{
		buff: data,
	}
}

// Len returns the number of bytes the stream currently holds.
//
// Revisions:
//   - 2026-01-20 23:00: initial creation
func (c *Codec) Len() int {
	return len(c.buff)
}

// Cap returns the capacity of the underlying buffer.
//
// Revisions:
//   - 2026-01-20 23:00: initial creation
func (c *Codec) Cap() int {
	return cap(c.buff)
}

// NumWritten returns the total number of bits written, partial bytes included.
//
// Revisions:
//   - 2026-01-20 23:00: initial creation
func (c *Codec) NumWritten() uint64 {
	return c.written
}

// NumRead returns the total number of bits read, partial bytes included.
//
// Revisions:
//   - 2026-01-20 23:00: initial creation
func (c *Codec) NumRead() uint64 {
	return c.read
}

// Bytes returns the bytes written so far, including a trailing partial byte
// whose unused bits are zero.
//
// The slice aliases the Codec's buffer rather than copying it, so a later Write
// may overwrite the trailing byte or move the whole buffer. A caller that keeps
// the result past the next Write copies it.
//
// Revisions:
//   - 2026-01-20 23:00: initial creation
//   - 2026-09-22 06:43: says that the result aliases the buffer, which callers
//     were relying on without the contract saying so
func (c *Codec) Bytes() []byte {
	if c.written == 0 {
		return nil
	}

	return c.buff
}

// String renders the Codec's state for a log line or a test failure.
//
// Revisions:
//   - 2026-01-20 23:00: initial creation
func (c *Codec) String() string {
	return fmt.Sprintf(
		"Codec{buff: len=%d, offset: %d, written: %d, read: %d}",
		len(c.buff),
		c.offset,
		c.written,
		c.read,
	)
}

// Write appends the least significant num bits of value, most significant first.
//
// num of 0, or above UINT64_BITS, is an error rather than a no-op: a caller that
// computed a width of zero has a bug the stream cannot encode its way out of.
//
// Revisions:
//   - 2026-01-20 23:00: initial creation
//   - 2026-09-22 06:43: splits the aligned and packed halves into _WriteAligned
//     and _WritePacked, and masks with a shift so a width of 64 no longer relies
//     on 1<<64 wrapping to zero
func (c *Codec) Write(num uint8, value uint64) error {
	if ENABLE_TRACE {
		c._Trace("ENTER", "Write", fmt.Sprintf("bits=%d value=%d", num, value))
		defer c._Trace("EXIT", "Write", "")
	}

	if num == 0 || num > UINT64_BITS {
		return ErrInvalidBitCount
	}

	value = value & (^uint64(0) >> (UINT64_BITS - num))

	if c.offset == 0 || c.offset == BITS_PER_BYTE {
		c._WriteAligned(num, value)
	} else {
		c._WritePacked(num, value)
	}

	c._IncrementWrite(uint64(num))

	return nil
}

// Read returns the next num bits, most significant first.
//
// num of 0 returns zero and no error, because a zero-width field is how X.691
// clause 11.5.4 encodes a range of one and a caller should not have to special
// case it.
//
// Revisions:
//   - 2026-01-20 23:00: initial creation
//   - 2026-09-22 06:43: takes the aligned path from an offset of zero as well as
//     BITS_PER_BYTE. The guard tested len(buff) == 0, which the short-buffer
//     check above it had already ruled out, so a fresh reader packed its first
//     read a bit at a time - and a fresh reader is every decoder's first field
func (c *Codec) Read(num uint8) (uint64, error) {
	if ENABLE_TRACE {
		c._Trace("ENTER", "Read", fmt.Sprintf("num=%d", num))
		defer c._Trace("EXIT", "Read", "")
	}

	if num == 0 {
		return 0, nil
	}

	if num > UINT64_BITS {
		return 0, ErrInvalidBitCount
	}

	if len(c.buff) == 0 {
		return 0, ErrShortBuffer
	}

	var (
		value uint64
		err   error
	)
	if c.offset == 0 || c.offset == BITS_PER_BYTE {
		value, err = c._ReadAligned(num)
	} else {
		value, err = c._ReadPacked(num)
	}

	if err != nil {
		return 0, err
	}

	c._IncrementRead(uint64(num))

	return value, nil
}

// WriteBytes appends whole octets, continuing from the current bit offset.
//
// It does not align first: X.691 clause 17.6 places a short octet string in a
// bit-field that is deliberately not octet-aligned, so alignment is the caller's
// decision and Align is how they make it.
//
// Revisions:
//   - 2026-01-20 23:00: initial creation
//   - 2026-09-22 06:43: carries a mid-byte payload a word at a time through
//     _WriteShifted instead of one Write call per byte
func (c *Codec) WriteBytes(data []byte) error {
	if ENABLE_TRACE {
		c._Trace("ENTER", "WriteBytes", fmt.Sprintf("len(data)=%d", len(data)))
		defer c._Trace("EXIT", "WriteBytes", "")
	}

	if len(data) == 0 {
		return nil
	}

	if c.offset == 0 || c.offset == BITS_PER_BYTE {
		c.buff = append(c.buff, data...)
		c.offset = BITS_PER_BYTE
	} else {
		c._WriteShifted(data)
	}

	c._IncrementWrite(uint64(len(data)) * BITS_PER_BYTE)

	return nil
}

// ReadBytes returns the next n whole octets, continuing from the current bit
// offset.
//
// Revisions:
//   - 2026-01-20 23:00: initial creation
//   - 2026-09-22 06:43: carries a mid-byte payload a word at a time through
//     _ReadShifted instead of one Read call per byte
func (c *Codec) ReadBytes(n int) ([]byte, error) {
	if ENABLE_TRACE {
		c._Trace("ENTER", "ReadBytes", fmt.Sprintf("n=%d", n))
		defer c._Trace("EXIT", "ReadBytes", "")
	}

	if n < 0 {
		return nil, ErrNegativeCount
	}

	if n == 0 {
		return []byte{}, nil
	}

	var (
		data []byte
		err  error
	)
	if c.offset == 0 || c.offset == BITS_PER_BYTE {
		data, err = c._ReadWhole(n)
	} else {
		data, err = c._ReadShifted(n)
	}

	if err != nil {
		return nil, err
	}

	c._IncrementRead(uint64(n) * BITS_PER_BYTE)

	return data, nil
}

// ReadView returns the next n octets, without copying them when it can.
//
// When the read is octet-aligned the result is a window onto the codec's own
// buffer - the same aliasing Bytes has, and the same buffer CreateReader was
// handed, so nothing new is shared. When it is not aligned the octets have to
// be shifted into being, and the result is the fresh slice ReadBytes returns.
// Either way the caller must treat the result as read-only and not keep it
// past the next call on the codec.
//
// It exists for a decoder that consumes a byte string and produces something
// else from it: with ReadBytes that is a copy per call whose only purpose is
// to be read once and dropped.
//
// Revisions:
//   - 2026-09-23 07:40: initial creation
func (c *Codec) ReadView(n int) ([]byte, error) {
	if ENABLE_TRACE {
		c._Trace("ENTER", "ReadView", fmt.Sprintf("n=%d", n))
		defer c._Trace("EXIT", "ReadView", "")
	}

	if c.offset != 0 && c.offset != BITS_PER_BYTE {
		return c.ReadBytes(n)
	}

	if n < 0 {
		return nil, ErrNegativeCount
	}

	if n == 0 {
		return []byte{}, nil
	}

	if c.offset == BITS_PER_BYTE {
		if len(c.buff) == 0 {
			return nil, ErrShortBuffer
		}

		c.buff = c.buff[1:]
		c.offset = 0
	}

	if len(c.buff) < n {
		return nil, ErrShortBuffer
	}

	data := c.buff[:n:n]
	c.buff = c.buff[n:]
	c._IncrementRead(uint64(n) * BITS_PER_BYTE)

	return data, nil
}

// Grow reserves room for at least n more bytes, so a caller that knows how
// much it is about to write can have the buffer grow once rather than double
// its way up through it. It never changes what the buffer holds; n at or
// below zero asks for nothing.
//
// Revisions:
//   - 2026-09-23 07:40: initial creation
func (c *Codec) Grow(n int) {
	if n <= 0 || cap(c.buff)-len(c.buff) >= n {
		return
	}

	c.buff = slices.Grow(c.buff, n)
}

// Align pads the current byte with zero bits so the next write starts a new one.
//
// The padding bits are already zero, so this only marks the byte full and counts
// the bits it skipped; the byte itself is appended by whichever Write comes next.
//
// Revisions:
//   - 2026-01-20 23:00: initial creation
func (c *Codec) Align() error {
	if ENABLE_TRACE {
		c._Trace("ENTER", "Align", "")
		defer c._Trace("EXIT", "Align", "")
	}

	if c.offset > 0 && c.offset < BITS_PER_BYTE {
		c._IncrementWrite(uint64(BITS_PER_BYTE - c.offset))
		c.offset = BITS_PER_BYTE
	}

	return nil
}

// Advance skips the rest of the current byte, the read counterpart of Align.
//
// The buffer is not advanced here; the next Read sees the full offset and does
// it, which keeps this O(1) and avoids reslicing a buffer nobody reads again.
//
// Revisions:
//   - 2026-01-20 23:00: initial creation
func (c *Codec) Advance() error {
	if ENABLE_TRACE {
		c._Trace("ENTER", "Advance", "")
		defer c._Trace("EXIT", "Advance", "")
	}

	if c.offset > 0 {
		c._IncrementRead(uint64(BITS_PER_BYTE - c.offset))
		c.offset = BITS_PER_BYTE
	}

	return nil
}

// _WriteAligned appends num bits that start on a byte boundary.
//
// Revisions:
//   - 2026-09-22 06:43: initial creation, split out of Write
func (c *Codec) _WriteAligned(num uint8, value uint64) {
	var (
		nbytes    = (int(num) + BITS_PER_BYTE - 1) / BITS_PER_BYTE
		remainder = num % BITS_PER_BYTE
		tmp       [UINT64_BYTES]byte
	)

	binary.BigEndian.PutUint64(tmp[:], value<<(UINT64_BITS-num))
	c.buff = append(c.buff, tmp[:nbytes]...)

	c.offset = remainder
	if c.offset == 0 {
		c.offset = BITS_PER_BYTE
	}
}

// _WritePacked appends num bits that start part-way through a byte.
//
// Revisions:
//   - 2026-09-22 06:43: initial creation, split out of Write
func (c *Codec) _WritePacked(num uint8, value uint64) {
	pending := num
	for pending > 0 {
		if c.offset == BITS_PER_BYTE {
			c._Grow(1)
			c.offset = 0
		}

		var (
			free  = BITS_PER_BYTE - c.offset
			nbits = min(pending, free)
			rest  = pending - nbits
			chunk = uint8(value>>rest) & (uint8(1)<<nbits - 1)
			pos   = len(c.buff) - 1
		)

		c.buff[pos] = c.buff[pos] | chunk<<(free-nbits)
		c.offset = c.offset + nbits
		pending = rest
	}
}

// _WriteShifted appends data to a buffer that ends part-way through a byte,
// carrying the bits across the boundary one 64-bit word at a time.
//
// The byte-at-a-time form this replaces cost a call, a bounds check and a
// two-iteration bit loop per byte. PER leaves the stream mid-byte before almost
// every octet string, because a preamble bit or a choice index precedes it, so
// that path is the ordinary one rather than the exception. Measured on a 4 KiB
// payload at a 3-bit offset: 32.1us for the byte loop, 3.9us once it worked a
// word at a time, 2.2us once it grew the buffer once instead of per word, and
// 0.19us once _ShiftBulk handed the middle of it to an AVX2 kernel.
//
// Revisions:
//   - 2026-09-22 06:43: initial creation
func (c *Codec) _WriteShifted(data []byte) {
	var (
		used  = c.offset & SHIFT_MASK
		free  = BITS_PER_BYTE - used
		high  = (UINT64_BITS - uint(used)) & UINT64_SHIFT_MASK
		last  = len(c.buff) - 1
		carry = uint64(c.buff[last] >> free)
	)

	// The trailing byte is rebuilt as the first byte of the shifted output, so
	// it is dropped and the whole result grown for in one go. Growing once and
	// storing beats appending per word: an append re-checks the capacity on
	// every iteration, which was most of the loop body.
	c.buff = c.buff[:last]
	c._Grow(len(data) + 1)

	var (
		out = c.buff[last:]
		idx = _ShiftBulk(out, data, used, carry)
	)

	// Whatever the kernel wrote, the word loop picks up from the byte after it,
	// with the carry taken from the last byte the kernel consumed.
	if idx > 0 {
		carry = uint64(data[idx-1]) & (uint64(1)<<used - 1)
	}

	for idx+UINT64_BYTES <= len(data) {
		word := binary.BigEndian.Uint64(data[idx:])
		binary.BigEndian.PutUint64(out[idx:], carry<<high|word>>used)
		carry = word & (uint64(1)<<used - 1)
		idx = idx + UINT64_BYTES
	}

	for ; idx < len(data); idx++ {
		word := uint64(data[idx])
		out[idx] = byte(carry<<free | word>>used)
		carry = word & (uint64(1)<<used - 1)
	}

	out[len(data)] = byte(carry << free)
}

// _ReadAligned returns num bits that start on a byte boundary.
//
// Revisions:
//   - 2026-09-22 06:43: initial creation, split out of Read
func (c *Codec) _ReadAligned(num uint8) (uint64, error) {
	if c.offset == BITS_PER_BYTE {
		c.buff = c.buff[1:]

		c.offset = 0
		if len(c.buff) == 0 {
			return 0, ErrShortBuffer
		}
	}

	nbytes := (int(num) + BITS_PER_BYTE - 1) / BITS_PER_BYTE
	if len(c.buff) < nbytes {
		return 0, ErrShortBuffer
	}

	var tmp [UINT64_BYTES]byte
	copy(tmp[:nbytes], c.buff[:nbytes])

	var (
		value     = binary.BigEndian.Uint64(tmp[:]) >> (UINT64_BITS - num)
		remainder = num % BITS_PER_BYTE
	)

	// One byte is deliberately left in the buffer: the offset says how much of
	// it has been used, and the next read advances past it.
	c.buff = c.buff[nbytes-1:]

	c.offset = remainder
	if c.offset == 0 {
		c.offset = BITS_PER_BYTE
	}

	return value, nil
}

// _ReadPacked returns num bits that start part-way through a byte.
//
// Revisions:
//   - 2026-09-22 06:43: initial creation, split out of Read
func (c *Codec) _ReadPacked(num uint8) (uint64, error) {
	var (
		value   uint64
		pending = num
	)

	for pending > 0 {
		if c.offset == BITS_PER_BYTE {
			c.buff = c.buff[1:]

			c.offset = 0
			if len(c.buff) == 0 {
				return 0, ErrShortBuffer
			}
		}

		var (
			left  = BITS_PER_BYTE - c.offset
			nbits = min(pending, left)
			mask  = uint8(1)<<nbits - 1
			bits  = uint64(c.buff[0]>>(left-nbits)) & uint64(mask)
		)

		value = value<<nbits | bits
		c.offset = c.offset + nbits
		pending = pending - nbits
	}

	return value, nil
}

// _ReadWhole returns n octets that start on a byte boundary.
//
// Revisions:
//   - 2026-09-22 06:43: initial creation, split out of ReadBytes
func (c *Codec) _ReadWhole(n int) ([]byte, error) {
	if c.offset == BITS_PER_BYTE {
		if len(c.buff) == 0 {
			return nil, ErrShortBuffer
		}

		c.buff = c.buff[1:]
		c.offset = 0
	}

	if len(c.buff) < n {
		return nil, ErrShortBuffer
	}

	data := make([]byte, n)
	copy(data, c.buff[:n])
	c.buff = c.buff[n:]

	return data, nil
}

// _ReadShifted returns n octets that start part-way through a byte, gathering
// them one 64-bit word at a time.
//
// The read counterpart of _WriteShifted, and the same measurement applies: the
// byte-at-a-time form cost a call and a bit loop per octet.
//
// Revisions:
//   - 2026-09-22 06:43: initial creation
//   - 2026-09-23 04:10: hands the middle of the buffer to the vector kernel,
//     the way _WriteShifted already did, and keeps the word loop for the tail
//   - 2026-09-23 07:40: the word loop writes each word straight into data; it
//     had been staging every one through an array and copying it across
func (c *Codec) _ReadShifted(n int) ([]byte, error) {
	// n octets starting part-way through a byte end inside the (n+1)th.
	if len(c.buff) < n+1 {
		return nil, ErrShortBuffer
	}

	var (
		used = c.offset
		free = BITS_PER_BYTE - used
		data = make([]byte, n)
		idx  = _ReadBulk(data, c.buff, used)
	)

	// Whatever the kernel filled, the word loop picks up from the byte after
	// it; the two agree on every byte, so there is no seam to reconcile.
	for idx+UINT64_BYTES <= n {
		var (
			word = binary.BigEndian.Uint64(c.buff[idx:])
			next = uint64(c.buff[idx+UINT64_BYTES])
		)
		binary.BigEndian.PutUint64(data[idx:], word<<used|next>>free)
		idx = idx + UINT64_BYTES
	}

	for ; idx < n; idx++ {
		data[idx] = c.buff[idx]<<used | c.buff[idx+1]>>free
	}

	c.buff = c.buff[n:]

	return data, nil
}

// _Grow makes room for n more bytes and extends the buffer over them.
//
// Capacity doubles rather than growing by n, so the total copied across a whole
// message stays linear in its length instead of quadratic.
//
// Revisions:
//   - 2026-01-20 23:00: initial creation
func (c *Codec) _Grow(n int) {
	if ENABLE_TRACE {
		c._Trace("ENTER", "_Grow", fmt.Sprintf("n=%d", n))
		defer c._Trace("EXIT", "_Grow", "")
	}

	if cap(c.buff) < len(c.buff)+n {
		size := max(cap(c.buff)*GROWTH_FACTOR, len(c.buff)+n)
		c.buff = slices.Grow(c.buff, size-len(c.buff))
	}

	c.buff = c.buff[:len(c.buff)+n]
}

// _IncrementRead adds bits to the count of bits read.
//
// Revisions:
//   - 2026-01-20 23:00: initial creation
func (c *Codec) _IncrementRead(bits uint64) {
	c.read += bits
}

// _IncrementWrite adds bits to the count of bits written.
//
// Revisions:
//   - 2026-01-20 23:00: initial creation
func (c *Codec) _IncrementWrite(bits uint64) {
	c.written += bits
}

// _Trace prints one line of Codec state when ENABLE_TRACE is on.
//
// Revisions:
//   - 2026-01-20 23:00: initial creation
func (c *Codec) _Trace(event, function, arguments string) {
	if !ENABLE_TRACE {
		return
	}

	state := fmt.Sprintf(
		"[%s %s] len=%d offset=%d written=%d read=%d",
		event,
		function,
		len(c.buff),
		c.offset,
		c.written,
		c.read,
	)
	if arguments != "" {
		state = state + " --> " + arguments
	}

	println(state)
}
