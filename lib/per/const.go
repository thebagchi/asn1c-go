package per

const (
	MAX_CONSTRAINED_LENGTH         = 65536           // ITU-T X.691 §11.9.3.3: max length encodable as constrained whole number (64K)
	FRAGMENT_SIZE                  = 16384           // ITU-T X.691 §11.9.4.2: fragment size for indefinite-length encoding (16K)
	RANGE_BITFIELD_MAX             = 0xFF            // §11.5.7.1: bit-field case, range <= 255
	RANGE_ONE_OCTET                = 0x100           // §11.5.7.2: one-octet aligned case, range == 256
	RANGE_TWO_OCTET_MIN            = 0x101           // §11.5.7.3: two-octet aligned case, range >= 257
	RANGE_TWO_OCTET_MAX            = 0x10000         // §11.5.7.3: two-octet aligned case, range <= 65536
	NORMALLY_SMALL_MAX             = 63              // §11.6.1: n <= 63 encoded with 0 prefix bit then 6 bits
	NORMALLY_SMALL_LENGTH_MAX      = 64              // §11.9.3.4: n <= 64 encoded as 6-bit (n-1)
	NORMALLY_SMALL_BITS            = 6               // §11.6.1/11.9.3.4: bit-field width for normally-small values
	UNCONSTRAINED_LENGTH_SHORT_MAX = 127             // §11.9.3.6: n <= 127, single-octet with bit 8 = 0
	LENGTH_LONG_FORM_FLAG          = 1 << 15         // §11.9.3.7: two-octet length prefix marker (10xxxxxxxxxxxxxx)
	LENGTH_FRAGMENT_FLAG           = 3 << 6          // §11.9.3.8: fragment length prefix marker (11xxxxxx)
	LENGTH_MSB_FLAG                = 0x80            // §11.9.4.2: bit 8 set means not short form
	LENGTH_FORM_MASK               = 0xC0            // §11.9.4.2: bits 8-7 mask for form detection
	LENGTH_LONG_FORM               = 0x80            // §11.9.4.2: 10xxxxxx pattern, two-octet long form (128-16383)
	LENGTH_SIX_BIT_MASK            = 0x3F            // §11.9.4.2: lower 6 bits value field in long and fragment octets
	REAL_PLUS_INFINITY             = 0x40            // X.690 §8.5.9: PLUS-INFINITY content octet
	REAL_MINUS_INFINITY            = 0x41            // X.690 §8.5.9: MINUS-INFINITY content octet
	REAL_NOT_A_NUMBER              = 0x42            // X.690 §8.5.9: NOT-A-NUMBER content octet
	REAL_MINUS_ZERO                = 0x43            // X.690 §8.5.9: minus zero content octet
	REAL_BINARY_SIGN_BIT           = 0x40            // X.690 §8.5.7.1: bit 7 of first octet is sign S
	DOUBLE_SIGN_BIT_POS            = 63              // IEEE 754: bit index of sign bit
	DOUBLE_MANTISSA_BITS           = 52              // IEEE 754: number of mantissa (fraction) bits
	DOUBLE_EXPONENT_MASK           = 0x7FF           // IEEE 754: 11-bit exponent field mask (bits 62-52)
	DOUBLE_MANTISSA_MASK           = 0xFFFFFFFFFFFFF // IEEE 754: 52-bit mantissa field mask (bits 51-0)
	DOUBLE_EXPONENT_BIAS           = 1023            // IEEE 754: exponent bias for normal numbers
	DOUBLE_SUBNORMAL_EXP           = -1022           // IEEE 754: effective exponent for subnormal numbers
	SIGN_BIT_24                    = 0x800000        // MSB (sign bit) of a 24-bit two's complement value
	TWOS_COMPLEMENT_24             = 1 << 24         // 2^24 for 24-bit two's complement sign extension
	BITSTRING_DIRECT_MAX_BITS      = 16              // §16.9: BIT STRING fixed length <= 16 bits needs no length determinant
	OCTET_STRING_DIRECT_MAX        = 2               // §17.6: OCTET STRING fixed length <= 2 octets needs no length determinant
)
