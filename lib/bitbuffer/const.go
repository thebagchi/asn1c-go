package bitbuffer

// Widths and sizes the bit stream is expressed in. They are named rather than
// written inline because a bare 8 in this package is ambiguous: it is a byte
// width in one line and a bit count in the next, and the two are not
// interchangeable when a read crosses a byte boundary.
const (
	BITS_PER_BYTE    = 8    // bits in a byte, and the value of a full offset
	UINT64_BITS      = 64   // bits in a uint64, the widest field Write and Read take
	UINT64_BYTES     = 8    // bytes in a uint64, the size of the staging arrays
	INITIAL_CAPACITY = 64   // bytes reserved by CreateWriter
	GROWTH_FACTOR    = 2    // buffer capacity multiplier, for O(1) amortised growth
	BYTE_MASK        = 0xFF // all bits of one byte

	// Masks that tell the compiler a shift count is in range. Go defines a
	// shift at or past the operand's width as zero, so without these it emits a
	// compare and a conditional clear beside every variable shift.
	SHIFT_MASK        = BITS_PER_BYTE - 1
	UINT64_SHIFT_MASK = UINT64_BITS - 1
)
