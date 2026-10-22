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

	// PEEL_READ_MIN is the rest, in bits after the open byte, above which a read takes the
	// open byte whole and the rest on a byte boundary. Below it the chunk loop measured
	// faster (7 bits) or the same (16 bits) (review P24). A field wider than
	// PEEL_FIELD_MIN has such a rest at every offset, so Read can test the width alone.
	PEEL_READ_MIN  = 16
	PEEL_FIELD_MIN = PEEL_READ_MIN + BITS_PER_BYTE - 1 // a wider field passes PEEL_READ_MIN

	// Masks that tell the compiler a shift count is in range. Go defines a
	// shift at or past the operand's width as zero, so without these it emits a
	// compare and a conditional clear beside every variable shift.
	SHIFT_MASK        = BITS_PER_BYTE - 1
	UINT64_SHIFT_MASK = UINT64_BITS - 1
)
