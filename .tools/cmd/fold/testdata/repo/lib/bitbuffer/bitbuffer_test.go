package bitbuffer_test

import (
	"bytes"
	"errors"
	"strconv"
	"testing"

	"github.com/thebagchi/asn1c-go/lib/bitbuffer"
)

// widths returns every field width Write and Read accept, which is the axis
// almost every case below is driven along.
//
// Revisions:
//   - 2026-09-22 06:43: initial creation
func widths() []uint8 {
	all := make([]uint8, bitbuffer.UINT64_BITS)
	for i := range all {
		all[i] = uint8(i + 1)
	}

	return all
}

// mask returns the largest value that fits in num bits.
//
// Revisions:
//   - 2026-09-22 06:43: initial creation
func mask(num uint8) uint64 {
	return ^uint64(0) >> (bitbuffer.UINT64_BITS - num)
}

// name builds a subtest name from a label and a number, so a failure says which
// width or offset it was.
//
// Revisions:
//   - 2026-09-22 06:43: initial creation
func name(label string, value uint8) string {
	return label + "_" + strconv.Itoa(int(value))
}

// payload returns a byte slice whose contents differ from byte to byte, so a
// shift that loses or duplicates one is visible in the comparison.
//
// Revisions:
//   - 2026-09-22 06:43: initial creation
func payload(size int) []byte {
	data := make([]byte, size)
	for i := range data {
		data[i] = byte(i*7 + 1)
	}

	return data
}

// TestWriteReadRoundTrip checks that every field width survives a write and a read.
//
// Revisions:
//   - 2026-09-22 06:43: initial creation
func TestWriteReadRoundTrip(t *testing.T) {
	cases := []struct {
		name  string
		value func(uint8) uint64
	}{
		{name: "zero", value: func(uint8) uint64 { return 0 }},
		{name: "width", value: func(num uint8) uint64 { return uint64(num) }},
		{name: "max", value: mask},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			writer := bitbuffer.CreateWriter()
			for _, num := range widths() {
				if err := writer.Write(num, tc.value(num)); err != nil {
					t.Fatalf("Write(%d): %v", num, err)
				}
			}

			total := uint64(bitbuffer.UINT64_BITS) * (bitbuffer.UINT64_BITS + 1) / 2
			if writer.NumWritten() != total {
				t.Errorf("NumWritten() = %d, want %d", writer.NumWritten(), total)
			}

			reader := bitbuffer.CreateReader(writer.Bytes())
			for _, num := range widths() {
				got, err := reader.Read(num)
				if err != nil {
					t.Fatalf("Read(%d): %v", num, err)
				}

				if want := tc.value(num); got != want {
					t.Errorf("Read(%d) = %d, want %d", num, got, want)
				}
			}

			if reader.NumRead() != total {
				t.Errorf("NumRead() = %d, want %d", reader.NumRead(), total)
			}
		})
	}
}

// TestWriteBytesReadBytes checks bulk octets at every starting bit offset.
//
// Revisions:
//   - 2026-09-22 06:43: initial creation
func TestWriteBytesReadBytes(t *testing.T) {
	for _, prefix := range widths() {
		t.Run(name("prefix", prefix), func(t *testing.T) {
			data := payload(37)

			writer := bitbuffer.CreateWriter()
			if err := writer.Write(prefix, mask(prefix)); err != nil {
				t.Fatalf("Write(%d): %v", prefix, err)
			}

			if err := writer.WriteBytes(data); err != nil {
				t.Fatalf("WriteBytes: %v", err)
			}

			reader := bitbuffer.CreateReader(writer.Bytes())
			if _, err := reader.Read(prefix); err != nil {
				t.Fatalf("Read(%d): %v", prefix, err)
			}

			got, err := reader.ReadBytes(len(data))
			if err != nil {
				t.Fatalf("ReadBytes: %v", err)
			}

			if !bytes.Equal(got, data) {
				t.Errorf("ReadBytes() = % x, want % x", got, data)
			}
		})
	}
}

// TestAlignPadsWithZeroBits checks that Align pads the current byte and starts a new one.
//
// Revisions:
//   - 2026-09-22 06:43: initial creation
func TestAlignPadsWithZeroBits(t *testing.T) {
	writer := bitbuffer.CreateWriter()
	if err := writer.Write(3, 5); err != nil {
		t.Fatalf("Write: %v", err)
	}

	if err := writer.Align(); err != nil {
		t.Fatalf("Align: %v", err)
	}

	if err := writer.Write(8, 0xAB); err != nil {
		t.Fatalf("Write: %v", err)
	}

	want := []byte{0xA0, 0xAB}
	if got := writer.Bytes(); !bytes.Equal(got, want) {
		t.Errorf("Bytes() = % x, want % x", got, want)
	}

	if writer.NumWritten() != 16 {
		t.Errorf("NumWritten() = %d, want 16", writer.NumWritten())
	}
}

// TestAdvanceSkipsToByteBoundary checks that Advance is the read counterpart of Align.
//
// Revisions:
//   - 2026-09-22 06:43: initial creation
func TestAdvanceSkipsToByteBoundary(t *testing.T) {
	reader := bitbuffer.CreateReader([]byte{0xA0, 0xAB})
	if _, err := reader.Read(3); err != nil {
		t.Fatalf("Read: %v", err)
	}

	if err := reader.Advance(); err != nil {
		t.Fatalf("Advance: %v", err)
	}

	got, err := reader.Read(8)
	if err != nil {
		t.Fatalf("Read: %v", err)
	}

	if got != 0xAB {
		t.Errorf("Read(8) = %#x, want 0xab", got)
	}

	if reader.NumRead() != 16 {
		t.Errorf("NumRead() = %d, want 16", reader.NumRead())
	}
}

// TestInvalidArguments checks the arguments Write, Read and ReadBytes refuse.
//
// Revisions:
//   - 2026-09-22 06:43: initial creation
func TestInvalidArguments(t *testing.T) {
	cases := []struct {
		name string
		call func() error
		want error
	}{
		{
			name: "write_zero_bits",
			call: func() error { return bitbuffer.CreateWriter().Write(0, 0) },
			want: bitbuffer.ErrInvalidBitCount,
		},
		{
			name: "write_too_many_bits",
			call: func() error { return bitbuffer.CreateWriter().Write(65, 0) },
			want: bitbuffer.ErrInvalidBitCount,
		},
		{
			name: "read_too_many_bits",
			call: func() error {
				_, err := bitbuffer.CreateReader([]byte{0x00}).Read(65)

				return err
			},
			want: bitbuffer.ErrInvalidBitCount,
		},
		{
			name: "read_empty",
			call: func() error {
				_, err := bitbuffer.CreateReader(nil).Read(1)

				return err
			},
			want: bitbuffer.ErrShortBuffer,
		},
		{
			name: "read_past_end",
			call: func() error {
				_, err := bitbuffer.CreateReader([]byte{0x00}).ReadBytes(4)

				return err
			},
			want: bitbuffer.ErrShortBuffer,
		},
		{
			name: "read_past_end_shifted",
			call: func() error {
				reader := bitbuffer.CreateReader([]byte{0x00, 0x00})
				if _, err := reader.Read(3); err != nil {
					return err
				}

				_, err := reader.ReadBytes(2)

				return err
			},
			want: bitbuffer.ErrShortBuffer,
		},
		{
			name: "read_negative",
			call: func() error {
				_, err := bitbuffer.CreateReader([]byte{0x00}).ReadBytes(-1)

				return err
			},
			want: bitbuffer.ErrNegativeCount,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if err := tc.call(); !errors.Is(err, tc.want) {
				t.Errorf("error = %v, want %v", err, tc.want)
			}
		})
	}
}

// TestReadZeroBitsIsNotAnError checks that a zero-width field reads as zero, which is how
// clause 11.5.4 encodes a range of one.
//
// Revisions:
//   - 2026-09-22 06:43: initial creation
func TestReadZeroBitsIsNotAnError(t *testing.T) {
	got, err := bitbuffer.CreateReader([]byte{0xFF}).Read(0)
	if err != nil {
		t.Fatalf("Read(0): %v", err)
	}

	if got != 0 {
		t.Errorf("Read(0) = %d, want 0", got)
	}
}

// TestRegressionShiftedBulkMatchesBitLoop guards lib/review.md finding 3.4: the
// word-at-a-time paths for a mid-byte WriteBytes and ReadBytes must produce
// exactly what the bit-at-a-time loop they replaced produced, at every offset.
//
// The lengths are chosen to straddle the 32-byte block the AVX2 kernel works
// in: shorter than one block, exactly one, one and a remainder, and several.
//
// Revisions:
//   - 2026-09-22 06:43: initial creation
func TestRegressionShiftedBulkMatchesBitLoop(t *testing.T) {
	for _, size := range []int{1, 7, 31, 32, 33, 37, 64, 65, 129, 1024} {
		for offset := uint8(1); offset < bitbuffer.BITS_PER_BYTE; offset++ {
			label := name("offset", offset) + "_" + name("len", byte(size%256))

			t.Run(label, func(t *testing.T) {
				checkShifted(t, payload(size), offset)
			})
		}
	}
}

// checkShifted compares a bulk write at the given bit offset against writing
// the same bytes one at a time, and then reads the result back.
//
// Revisions:
//   - 2026-09-22 09:12: initial creation, split out of the case above so the
//     vector kernel could be driven at lengths either side of its block size
func checkShifted(t *testing.T, data []byte, offset uint8) {
	t.Helper()

	bulk := bitbuffer.CreateWriter()
	if err := bulk.Write(offset, mask(offset)); err != nil {
		t.Fatalf("Write: %v", err)
	}

	if err := bulk.WriteBytes(data); err != nil {
		t.Fatalf("WriteBytes: %v", err)
	}

	loop := bitbuffer.CreateWriter()
	if err := loop.Write(offset, mask(offset)); err != nil {
		t.Fatalf("Write: %v", err)
	}

	for _, b := range data {
		err := loop.Write(bitbuffer.BITS_PER_BYTE, uint64(b))
		if err != nil {
			t.Fatalf("Write: %v", err)
		}
	}

	var (
		fast = bulk.Bytes()
		slow = loop.Bytes()
	)
	if !bytes.Equal(fast, slow) {
		t.Fatalf("WriteBytes = % x, bit loop = % x", fast, slow)
	}

	if bulk.NumWritten() != loop.NumWritten() {
		t.Errorf("NumWritten = %d, want %d",
			bulk.NumWritten(), loop.NumWritten())
	}

	reader := bitbuffer.CreateReader(bulk.Bytes())
	if _, err := reader.Read(offset); err != nil {
		t.Fatalf("Read: %v", err)
	}

	got, err := reader.ReadBytes(len(data))
	if err != nil {
		t.Fatalf("ReadBytes: %v", err)
	}

	if !bytes.Equal(got, data) {
		t.Errorf("ReadBytes = % x, want % x", got, data)
	}
}

// TestRegressionFirstReadIsAligned guards lib/review.md finding 3.3: a reader
// whose offset is zero takes the aligned path, so the first read of every
// message is not unpacked a bit at a time. The observable part is the value,
// which the two paths must agree on for every width.
//
// Revisions:
//   - 2026-09-22 06:43: initial creation
func TestRegressionFirstReadIsAligned(t *testing.T) {
	data := payload(16)

	for _, num := range widths() {
		t.Run(name("bits", num), func(t *testing.T) {
			fresh := bitbuffer.CreateReader(data)

			direct, err := fresh.Read(num)
			if err != nil {
				t.Fatalf("Read(%d): %v", num, err)
			}

			packed := bitbuffer.CreateReader(data)

			var want uint64

			for i := uint8(0); i < num; i++ {
				bit, err := packed.Read(1)
				if err != nil {
					t.Fatalf("Read(1): %v", err)
				}

				want = want<<1 | bit
			}

			if direct != want {
				t.Errorf("Read(%d) = %#x, want %#x", num, direct, want)
			}
		})
	}
}
