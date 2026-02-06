package per

import (
	"testing"
)

// TestMinimumOctetNonNegativeBinaryIntegerLength validates the calculation
// by comparing the math/bits implementation against the for-loop approach
func TestMinimumOctetNonNegativeBinaryIntegerLength(t *testing.T) {
	test := func(value uint64, expected int, description string) {
		t.Run(description, func(t *testing.T) {
			result := OctetsNonNegativeBinaryIntegerLength(value)
			if result != expected {
				t.Errorf("OctetsNonNegativeBinaryIntegerLength(%d) = %d, want %d", value, result, expected)
			}
		})
	}
	test(0, 1, "0 requires 1 octet")
	test(1, 1, "1 fits in 1 octet")
	test(0xFF, 1, "255 (max 1 octet)")
	test(0x100, 2, "256 (needs 2 octets)")
	test(0xFFFF, 2, "65535 (max 2 octets)")
	test(0x10000, 3, "65536 (needs 3 octets)")
	test(0xFFFFFF, 3, "16777215 (max 3 octets)")
	test(0x1000000, 4, "16777216 (needs 4 octets)")
	test(0xFFFFFFFF, 4, "max uint32")
	test(0x100000000, 5, "requires 5 octets")
	test(0xFFFFFFFFFFFFFFFF, 8, "max uint64")
	test(0x8000000000000000, 8, "high bit set")
	test(0x7F, 1, "127 (7 bits, fits in 1 octet)")
	test(0x80, 1, "128 (8 bits, fits in 1 octet)")
	test(0x01FF, 2, "511 (9 bits, needs 2 octets)")
}

// TestBitsTwosComplementBinaryInteger validates the calculation
// of minimum bits needed for 2's complement signed integer representation
func TestBitsTwosComplementBinaryInteger(t *testing.T) {
	test := func(value int64, expected int, description string) {
		t.Run(description, func(t *testing.T) {
			result := BitsTwosComplementBinaryInteger(value)
			if result != expected {
				t.Errorf("BitsTwosComplementBinaryInteger(%d) = %d, want %d", value, result, expected)
			}
		})
	}
	// Zero
	test(0, 1, "zero")
	// Positive values
	test(1, 2, "positive 1 (01 - sign + magnitude)")
	test(2, 3, "positive 2 (010)")
	test(3, 3, "positive 3 (011)")
	test(4, 4, "positive 4 (0100)")
	test(7, 4, "positive 7 (0111)")
	test(8, 5, "positive 8 (01000)")
	// Negative values (using spec 11.4.6 logic: bits.Len64(^value) + 1)
	test(-1, 1, "negative -1 (1)")
	test(-2, 2, "negative -2 (10)")
	test(-3, 3, "negative -3 (101 with sign extension)")
	test(-4, 3, "negative -4 (100)")
	test(-5, 4, "negative -5 (1011 with sign extension)")
	test(-8, 4, "negative -8 (1000)")
}

// TestOctetsTwosComplementBinaryInteger validates the calculation
// for 2's complement signed integer encoding
func TestOctetsTwosComplementBinaryInteger(t *testing.T) {
	test := func(value int64, expected int, description string) {
		t.Run(description, func(t *testing.T) {
			result := OctetsTwosComplementBinaryInteger(value)
			if result != expected {
				t.Errorf("OctetsTwosComplementBinaryInteger(%d) = %d, want %d", value, result, expected)
			}
		})
	}
	// Zero
	test(0, 1, "zero")
	// Positive values
	test(1, 1, "positive 1")
	test(63, 1, "positive 63 (0x3F - fits in 1 octet with sign bit)")
	test(64, 1, "positive 64 (0x40 - still fits in 1 octet)")
	test(127, 1, "positive 127 (0x7F - max positive for 1 octet)")
	test(128, 2, "positive 128 (0x80 - needs 2 octets, sign bit conflict)")
	test(255, 2, "positive 255 (0xFF - needs 2 octets)")
	test(32767, 2, "positive 32767 (0x7FFF - max positive for 2 octets)")
	test(32768, 3, "positive 32768 (0x8000 - needs 3 octets)")
	test(8388607, 3, "positive 8388607 (0x7FFFFF - max positive for 3 octets)")
	test(8388608, 4, "positive 8388608 (0x800000 - needs 4 octets)")
	test(2147483647, 4, "positive 2147483647 (0x7FFFFFFF - max int32)")
	test(2147483648, 5, "positive 2147483648 (0x80000000 - needs 5 octets)")
	test(9223372036854775807, 8, "positive 9223372036854775807 (max int64)")
	// Negative values
	test(-1, 1, "negative -1 (0xFF - fits in 1 octet)")
	test(-64, 1, "negative -64 (0xC0 - fits in 1 octet)")
	test(-128, 1, "negative -128 (0x80 - min negative for 1 octet)")
	test(-129, 2, "negative -129 (0xFF7F - needs 2 octets)")
	test(-255, 2, "negative -255 (needs 2 octets)")
	test(-256, 2, "negative -256 (0xFF00 - fits in 2 octets)")
	test(-32768, 2, "negative -32768 (0x8000 - min negative for 2 octets)")
	test(-32769, 3, "negative -32769 (needs 3 octets)")
	test(-8388608, 3, "negative -8388608 (0x800000 - min negative for 3 octets)")
	test(-8388609, 4, "negative -8388609 (needs 4 octets)")
	test(-2147483648, 4, "negative -2147483648 (0x80000000 - min int32)")
	test(-2147483649, 5, "negative -2147483649 (needs 5 octets)")
	test(-9223372036854775808, 8, "negative -9223372036854775808 (min int64)")
}
