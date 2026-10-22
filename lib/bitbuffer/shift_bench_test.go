package bitbuffer_test

import (
	"strconv"
	"testing"

	"github.com/thebagchi/asn1c-go/lib/bitbuffer"
)

// The payload sizes the shifted paths are timed over. 64 bytes never reaches a
// vector kernel, so it measures the scalar tail on its own; the two larger ones
// are where a kernel runs, and where the choice of lane width would show.
var (
	BENCH_SIZES = []int{64, 4096, 65536}
)

// BENCH_OFFSET puts the codec three bits into a byte, so every WriteBytes and
// ReadBytes below takes the shifted path rather than the aligned copy.
const (
	BENCH_OFFSET = 3
)

// BenchmarkWriteBytesMisaligned times WriteBytes from part-way through a byte,
// which is the path _WriteShifted and its kernel take.
//
// The writer is created inside the loop because the codec has no reset, and
// that allocation is the same in every variant being compared, so it cancels.
//
// Revisions:
//   - 2026-09-23 03:36: initial creation
func BenchmarkWriteBytesMisaligned(b *testing.B) {
	for _, size := range BENCH_SIZES {
		data := _Payload(size)

		b.Run(
			strconv.Itoa(size),
			func(b *testing.B) {
				b.SetBytes(int64(size))
				b.ReportAllocs()

				for b.Loop() {
					var (
						writer = bitbuffer.CreateWriter()

						err = writer.Write(
							BENCH_OFFSET,
							_Mask(BENCH_OFFSET),
						)
					)
					if err != nil {
						b.Fatal(err)
					}

					if err := writer.WriteBytes(data); err != nil {
						b.Fatal(err)
					}
				}
			},
		)
	}
}

// BenchmarkReadBytesMisaligned times ReadBytes from part-way through a byte,
// which is the path _ReadShifted takes. The encoded buffer is built once,
// outside the timed loop.
//
// Revisions:
//   - 2026-09-23 03:36: initial creation
func BenchmarkReadBytesMisaligned(b *testing.B) {
	for _, size := range BENCH_SIZES {
		encoded := _Shifted(
			b,
			_Payload(size),
		)

		b.Run(
			strconv.Itoa(size),
			func(b *testing.B) {
				b.SetBytes(int64(size))
				b.ReportAllocs()

				for b.Loop() {
					reader := bitbuffer.CreateReader(encoded)

					if _, err := reader.Read(BENCH_OFFSET); err != nil {
						b.Fatal(err)
					}

					if _, err := reader.ReadBytes(size); err != nil {
						b.Fatal(err)
					}
				}
			},
		)
	}
}

// shifted encodes data behind BENCH_OFFSET bits, so a reader has to shift it
// back out.
//
// Revisions:
//   - 2026-09-23 03:36: initial creation
func _Shifted(
	b *testing.B,
	data []byte,
) []byte {
	b.Helper()

	writer := bitbuffer.CreateWriter()

	if err := writer.Write(
		BENCH_OFFSET,
		_Mask(BENCH_OFFSET),
	); err != nil {
		b.Fatal(err)
	}

	if err := writer.WriteBytes(data); err != nil {
		b.Fatal(err)
	}

	return writer.Bytes()
}
