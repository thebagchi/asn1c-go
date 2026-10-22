package bitbuffer

import (
	"bytes"
	"encoding/binary"
	"strconv"
	"testing"
)

// This file is an internal test because _WritePacked and _ReadPacked are unexported.
// The peeled form fills the open byte, then uses the aligned word path for the rest.

const (
	PEEL_OFFSET = 3
	PEEL_FIELDS = 256
)

// TestPeel_MatchesWrite checks the peeled write and read against Write and Read.
// The offset is 1 to 7, so the field starts inside a byte. Widths stop at 64.
//
// Revisions:
//   - 2026-10-21 03:13: initial creation
func TestPeel_MatchesWrite(t *testing.T) {
	for offset := uint8(1); offset < BITS_PER_BYTE; offset++ {
		for width := uint8(1); width <= UINT64_BITS; width++ {
			var (
				value  = ^uint64(0) >> (UINT64_BITS - width)
				now    = CreateWriter()
				peeled = CreateWriter()
			)

			if err := now.Write(
				offset,
				1,
			); err != nil {
				t.Fatal(err)
			}

			if err := peeled.Write(
				offset,
				1,
			); err != nil {
				t.Fatal(err)
			}

			if err := now.Write(
				width,
				value,
			); err != nil {
				t.Fatal(err)
			}

			if err := peeled._WritePeeled(
				width,
				value,
			); err != nil {
				t.Fatal(err)
			}

			if !bytes.Equal(
				now.Bytes(),
				peeled.Bytes(),
			) {
				t.Fatalf(
					"offset %d width %d now %x peeled %x",
					offset,
					width,
					now.Bytes(),
					peeled.Bytes(),
				)
			}

			reader := CreateReader(peeled.Bytes())
			if _, err := reader.Read(offset); err != nil {
				t.Fatal(err)
			}

			got, err := reader._ReadPeeled(width)
			if err != nil {
				t.Fatal(err)
			}

			if got != value {
				t.Fatalf(
					"offset %d width %d read %x want %x",
					offset,
					width,
					got,
					value,
				)
			}
		}
	}
}

// BenchmarkPeelWrite times one misaligned field through _WritePacked and
// through the peeled form. The first Write plants the offset. It is in both.
//
// Revisions:
//   - 2026-10-21 03:13: initial creation
func BenchmarkPeelWrite(b *testing.B) {
	for _, width := range PEEL_WIDTHS {
		value := ^uint64(0) >> (UINT64_BITS - width)
		b.Run(
			"now/"+strconv.Itoa(int(width)),
			func(b *testing.B) {
				_BenchPeelWrite(
					b,
					width,
					func(codec *Codec) {
						if err := codec.Write(
							width,
							value,
						); err != nil {
							b.Fatal(err)
						}
					},
				)
			},
		)
		b.Run(
			"peel/"+strconv.Itoa(int(width)),
			func(b *testing.B) {
				_BenchPeelWrite(
					b,
					width,
					func(codec *Codec) {
						if err := codec._WritePeeled(
							width,
							value,
						); err != nil {
							b.Fatal(err)
						}
					},
				)
			},
		)
	}
}

// BenchmarkPeelRead times one misaligned field through _ReadPacked and
// through the peeled form. The buffer is built once, outside the timed loop.
//
// Revisions:
//   - 2026-10-21 03:13: initial creation
func BenchmarkPeelRead(b *testing.B) {
	for _, width := range PEEL_WIDTHS {
		encoded := _PeelEncoded(
			b,
			width,
		)
		b.Run(
			"now/"+strconv.Itoa(int(width)),
			func(b *testing.B) {
				_BenchPeelRead(
					b,
					width,
					encoded,
					func(codec *Codec) {
						if _, err := codec.Read(width); err != nil {
							b.Fatal(err)
						}
					},
				)
			},
		)
		b.Run(
			"peel/"+strconv.Itoa(int(width)),
			func(b *testing.B) {
				_BenchPeelRead(
					b,
					width,
					encoded,
					func(codec *Codec) {
						if _, err := codec._ReadPeeled(width); err != nil {
							b.Fatal(err)
						}
					},
				)
			},
		)
	}
}

// PEEL_WIDTHS are the field widths a mid-byte Write and Read take.
// 7 is one character. 64 is the widest field the codec takes.
var (
	PEEL_WIDTHS = []uint8{7, 16, 32, 64}
)

// _WritePeeled fills the open byte, then writes the rest on a byte boundary.
//
// Revisions:
//   - 2026-10-21 03:13: initial creation
func (c *Codec) _WritePeeled(
	num uint8,
	value uint64,
) error {
	if num == 0 || num > UINT64_BITS {
		return ErrInvalidBitCount
	}

	value = value & (^uint64(0) >> (UINT64_BITS - num))

	free := BITS_PER_BYTE - c.offset
	if num <= free {
		c._WritePacked(
			num,
			value,
		)
		c._IncrementWrite(uint64(num))

		return nil
	}

	var (
		rest = num - free
		low  = value & (^uint64(0) >> (UINT64_BITS - rest))
	)

	c.buff[len(c.buff)-1] |= byte(value >> rest)
	c.offset = BITS_PER_BYTE

	nbytes := (int(rest) + BITS_PER_BYTE - 1) / BITS_PER_BYTE
	c._Grow(nbytes)

	var tmp [UINT64_BYTES]byte
	binary.BigEndian.PutUint64(
		tmp[:],
		low<<(UINT64_BITS-rest),
	)
	copy(
		c.buff[len(c.buff)-nbytes:],
		tmp[:nbytes],
	)

	c.offset = rest % BITS_PER_BYTE
	if c.offset == 0 {
		c.offset = BITS_PER_BYTE
	}

	c._IncrementWrite(uint64(num))

	return nil
}

// _ReadPeeled reads the open byte, then reads the rest on a byte boundary.
//
// Revisions:
//   - 2026-10-21 03:13: initial creation
func (c *Codec) _ReadPeeled(num uint8) (uint64, error) {
	free := BITS_PER_BYTE - c.offset
	if num <= free {
		value, err := c._ReadPacked(num)
		if err != nil {
			return 0, err
		}

		c._IncrementRead(uint64(num))

		return value, nil
	}

	head := uint64(c.buff[0]) & ((uint64(1) << free) - 1)
	c.offset = BITS_PER_BYTE

	tail, err := c._ReadAligned(num - free)
	if err != nil {
		return 0, err
	}

	c._IncrementRead(uint64(num))

	return head<<(num-free) | tail, nil
}

// _BenchPeelWrite times PEEL_FIELDS writes after one planted offset.
//
// Revisions:
//   - 2026-10-21 03:13: initial creation
func _BenchPeelWrite(
	b *testing.B,
	width uint8,
	write func(*Codec),
) {
	b.Helper()

	b.SetBytes(int64(width) * PEEL_FIELDS)
	b.ReportAllocs()

	for b.Loop() {
		codec := CreateWriter()
		if err := codec.Write(
			PEEL_OFFSET,
			1,
		); err != nil {
			b.Fatal(err)
		}

		for range PEEL_FIELDS {
			write(codec)
		}
	}
}

// _BenchPeelRead times PEEL_FIELDS reads after one planted offset.
//
// Revisions:
//   - 2026-10-21 03:13: initial creation
func _BenchPeelRead(
	b *testing.B,
	width uint8,
	encoded []byte,
	read func(*Codec),
) {
	b.Helper()

	b.SetBytes(int64(width) * PEEL_FIELDS)
	b.ReportAllocs()

	for b.Loop() {
		codec := CreateReader(encoded)
		if _, err := codec.Read(PEEL_OFFSET); err != nil {
			b.Fatal(err)
		}

		for range PEEL_FIELDS {
			read(codec)
		}
	}
}

// _PeelEncoded builds the buffer both read paths consume.
//
// Revisions:
//   - 2026-10-21 03:13: initial creation
func _PeelEncoded(
	b *testing.B,
	width uint8,
) []byte {
	b.Helper()

	var (
		value = ^uint64(0) >> (UINT64_BITS - width)

		codec = CreateWriter()
	)
	if err := codec.Write(
		PEEL_OFFSET,
		1,
	); err != nil {
		b.Fatal(err)
	}

	for range PEEL_FIELDS {
		if err := codec.Write(
			width,
			value,
		); err != nil {
			b.Fatal(err)
		}
	}

	return codec.Bytes()
}
