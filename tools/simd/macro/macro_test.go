package macro_test

import (
	"bytes"
	"encoding/binary"
	"strconv"
	"testing"

	"github.com/thebagchi/asn1c-go/tools/simd/macro"
)

// reference is the obvious way to do the same shift, one word at a time. The
// macro kernel is only trustworthy against something this plain.
//
// Revisions:
//   - 2026-09-22 09:12: initial creation
func reference(out, data []byte, used uint8, carry uint64) {
	var (
		free = 8 - used
		high = (64 - uint(used)) & 63
		idx  = 0
	)

	for idx+8 <= len(data) {
		word := binary.BigEndian.Uint64(data[idx:])
		binary.BigEndian.PutUint64(out[idx:], carry<<high|word>>used)
		carry = word & (uint64(1)<<used - 1)
		idx += 8
	}

	for ; idx < len(data); idx++ {
		word := uint64(data[idx])
		out[idx] = byte(carry<<free | word>>used)
		carry = word & (uint64(1)<<used - 1)
	}

	out[len(data)] = byte(carry << free)
}

// payload returns bytes that differ from one another, so a shift that loses or
// duplicates one shows up.
//
// Revisions:
//   - 2026-09-22 09:12: initial creation
func payload(size int) []byte {
	data := make([]byte, size)
	for i := range data {
		data[i] = byte(i*7 + 3)
	}

	return data
}

// TestShiftMatchesReference checks the macro kernel against the plain loop, at
// lengths either side of the 32-byte block it works in.
//
// Revisions:
//   - 2026-09-22 09:12: initial creation
func TestShiftMatchesReference(t *testing.T) {
	sizes := []int{1, 7, 31, 32, 33, 64, 65, 129, 1000, 4096}

	for _, size := range sizes {
		for used := uint8(1); used < 8; used++ {
			name := strconv.Itoa(size) + "_bits_" + strconv.Itoa(int(used))

			t.Run(name, func(t *testing.T) {
				var (
					data  = payload(size)
					carry = uint64(5) & (uint64(1)<<used - 1)
					want  = make([]byte, size+1)
					got   = make([]byte, size+1)
				)

				reference(want, data, used, carry)
				macro.Shift(got, data, used, carry)

				if !bytes.Equal(got, want) {
					t.Errorf("shift = % x, want % x", got, want)
				}
			})
		}
	}
}
