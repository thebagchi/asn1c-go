package per

// Widths the encoding is expressed in, and the limits that follow from them.
//
// MAX_VALUE_OCTETS is the width of the widest integer this package represents.
// A length determinant may name more octets than that, and a decoder that
// multiplies such a count by BITS_PER_BYTE without checking it silently wraps:
// 32 octets becomes a request for zero bits, which reads nothing and reports no
// error. The constant exists so that check has a name to compare against.
const (
	BITS_PER_BYTE     = 8
	DOUBLE_OCTET_BITS = 16
	UINT64_BITS       = 64
	UINT64_BYTES      = 8
	MAX_VALUE_OCTETS  = 8
	DECIMAL_BASE      = 10
	NIBBLE_BITS       = 4
	NIBBLE_MAX        = 0x0F
)

// X.691 clause 11.5.7: how the range of a constrained whole number selects its
// encoding in the ALIGNED variant.
const (
	RANGE_BITFIELD_MAX  = 0xFF    // 11.5.7.1, bit-field case
	RANGE_ONE_OCTET     = 0x100   // 11.5.7.2, one-octet case
	RANGE_TWO_OCTET_MIN = 0x101   // 11.5.7.3, two-octet case, lower end
	RANGE_TWO_OCTET_MAX = 0x10000 // 11.5.7.3, two-octet case, upper end
)

// X.691 clauses 11.6 and 11.9: normally small numbers and length determinants.
//
// MAX_CONSTRAINED_LENGTH is the 64K that clause 11.9.3.1 uses to decide whether
// a length is encoded as a constrained whole number or as an unconstrained
// determinant; FRAGMENT_SIZE is the 16K unit that clause 11.9.3.8 fragments in.
const (
	MAX_CONSTRAINED_LENGTH         = 65536
	FRAGMENT_SIZE                  = 16384
	FRAGMENT_MULTIPLIER_MIN        = 1
	FRAGMENT_MULTIPLIER_MAX        = 4
	NORMALLY_SMALL_MAX             = 63  // 11.6.1, n encodable in six bits
	NORMALLY_SMALL_LENGTH_MAX      = 64  // 11.9.3.4, n encodable as six-bit n-1
	NORMALLY_SMALL_BITS            = 6   // 11.6.1 and 11.9.3.4, the bit-field width
	UNCONSTRAINED_LENGTH_SHORT_MAX = 127 // 11.9.3.6, single-octet form
)

// X.691 clause 11.9.3: the bit patterns that distinguish the three forms of an
// unconstrained length determinant.
const (
	LENGTH_LONG_FORM_FLAG = 1 << 15 // 11.9.3.7, sets bit 8 and clears bit 7
	LENGTH_FRAGMENT_FLAG  = 3 << 6  // 11.9.3.8, sets bits 8 and 7
	LENGTH_MSB_FLAG       = 0x80    // bit 8, set on every form but the short one
	LENGTH_FORM_MASK      = 0xC0    // bits 8 and 7, which name the form
	LENGTH_LONG_FORM      = 0x80    // bits 8 and 7 as 10, the two-octet form
	LENGTH_SIX_BIT_MASK   = 0x3F    // bits 6 to 1, the value the octet carries
)

// X.691 clauses 16.9 and 17.6: the fixed sizes that need no length determinant
// and take no alignment.
const (
	BITSTRING_DIRECT_MAX_BITS = 16
	OCTET_STRING_DIRECT_MAX   = 2
	ALPHABET_INDEX_SIZE       = 128 // every ordered alphabet of clause 30.4 is ASCII
	CHAR_ALIGN_BITS           = 16  // 30.4.7, a variable length aligns at this width
	CHAR_ALIGN_FIXED          = 17  // 30.4.6, a fixed length aligns only above it
)

// X.690 clause 8.5: the REAL contents octets, which X.691 clause 15.2 carries
// unchanged behind a length determinant.
const (
	REAL_PLUS_INFINITY    = 0x40 // 8.5.9, the whole contents octet
	REAL_MINUS_INFINITY   = 0x41 // 8.5.9
	REAL_NOT_A_NUMBER     = 0x42 // 8.5.9
	REAL_MINUS_ZERO       = 0x43 // 8.5.9
	REAL_BINARY_FLAG      = 0x80 // 8.5.6 a), bit 8 set means the binary form
	REAL_SPECIAL_FLAG     = 0x40 // 8.5.6 c), bit 7 set with bit 8 clear
	REAL_BINARY_SIGN_BIT  = 0x40 // 8.5.7.1, bit 7 set means the mantissa is negative
	REAL_BASE_SHIFT       = 4    // 8.5.7.2, bits 6 and 5 carry the base
	REAL_BASE_MASK        = 0x03
	REAL_SCALE_SHIFT      = 2 // 8.5.7.3, bits 4 and 3 carry the scaling factor
	REAL_SCALE_MASK       = 0x03
	REAL_EXPONENT_MASK    = 0x03 // 8.5.7.5, bits 2 and 1 carry the exponent form
	REAL_EXPONENT_ONE     = 0    // 8.5.7.5 a), one exponent octet
	REAL_EXPONENT_TWO     = 1    // 8.5.7.5 b), two exponent octets
	REAL_EXPONENT_THREE   = 2    // 8.5.7.5 c), three exponent octets
	REAL_EXPONENT_LONG    = 3    // 8.5.7.5 d), an exponent length octet follows
	REAL_BASE_SELECT_2    = 0    // 8.5.7.2, bits 6 and 5 as 00
	REAL_BASE_SELECT_8    = 1    // 8.5.7.2, bits 6 and 5 as 01
	REAL_BASE_SELECT_16   = 2    // 8.5.7.2, bits 6 and 5 as 10
	REAL_BASE_TWO         = 2
	REAL_BASE_EIGHT       = 8
	REAL_BASE_SIXTEEN     = 16
	REAL_BASE_TEN         = 10
	REAL_BASE_EIGHT_LOG   = 3 // base 8 is 2^3, so an exponent scales by three bits
	REAL_BASE_SIXTEEN_LOG = 4
	REAL_NR3_FORM         = 0x03 // 8.5.8, ISO 6093 NR3 in bits 6 to 1
)

// IEEE 754 binary64, which is where MakeReal takes a mantissa and exponent from.
const (
	DOUBLE_SIGN_BIT_POS  = 63
	DOUBLE_MANTISSA_BITS = 52
	DOUBLE_EXPONENT_MASK = 0x7FF
	DOUBLE_MANTISSA_MASK = 0xFFFFFFFFFFFFF
	DOUBLE_EXPONENT_BIAS = 1023
	DOUBLE_SUBNORMAL_EXP = -1022
)

// Two's complement sign extension for the three-octet exponent form, which is
// the one width Go has no integer type for.
const (
	SIGN_BIT_24        = 0x800000
	TWOS_COMPLEMENT_24 = 1 << 24
	EXPONENT_24_OCTETS = 3
)

// DER, which X.691 clauses 15 and 24 borrow contents octets from.
const (
	DER_HEADER_OCTETS = 2 // an identifier octet and a short-form length octet
)

// The alphabets of X.691 clause 30.4, as X.680 clause 43 numbers their
// characters. A range is inclusive of both ends.
const (
	IA5_MAX       = 0x7F   // IA5String, the whole of ISO 646
	VISIBLE_MIN   = 0x20   // VisibleString, space
	VISIBLE_MAX   = 0x7E   // VisibleString, tilde
	PRINTABLE_MIN = 0x20   // PrintableString, space
	PRINTABLE_MAX = 0x7A   // PrintableString, lowercase z
	NUMERIC_MIN   = 0x20   // NumericString, space
	NUMERIC_MAX   = 0x39   // NumericString, digit nine
	BMP_MAX       = 0xFFFF // BMPString, the basic multilingual plane
)

// ASCII_ZEROS is the padding a partial byte of bit string text takes, as a
// value to copy rather than a loop to run: Go turns a zero fill into a memclr
// but leaves a non-zero one as a loop.
var (
	ASCII_ZEROS = [BITS_PER_BYTE]byte{'0', '0', '0', '0', '0', '0', '0', '0'}
)

// Lane constants for the byte-parallel conversions in types.go.
//
// Each names one 64-bit word treated as eight independent byte lanes. They are
// gathered here because the arithmetic that uses them is only readable if the
// masks are named: BYTE_LANES is not a number, it is "the low byte of every
// 16-bit group", and the shift beside it is what moves a piece between lanes.
const (
	HALF_SHIFT       = 16                 // spacing step, two bytes
	HALF_LANES       = 0x0000FFFF0000FFFF // the low half of each 32-bit group
	BYTE_LANES       = 0x00FF00FF00FF00FF // the low byte of each 16-bit group
	NIBBLE_LANES     = 0x0F0F0F0F0F0F0F0F // the low nibble of each byte
	LOW_BIT_LANES    = 0x0101010101010101 // the low bit of each byte
	ASCII_ZERO_LANES = 0x3030303030303030 // '0' in each byte
	NINE_CARRY       = 0x0606060606060606 // added to carry out of a nibble above nine
	ALPHA_OFFSET     = 39                 // 'a' - '0' - 10, the digit-to-letter gap
	BIT_SPREAD_PICK  = 0x8040201008040201 // lane i keeps bit 7-i, leading bit first
	BIT_SPREAD_BIAS  = 0x7F7F7F7F7F7F7F7F // added to carry out of a non-zero lane
	BIT_SPREAD_SHIFT = 7                  // moves that carry down to the low bit
	BIT_GATHER       = 0x0102040810204080 // sums eight one-bit lanes into the top byte
	BIT_GATHER_SHIFT = 56                 // brings that byte down
)
