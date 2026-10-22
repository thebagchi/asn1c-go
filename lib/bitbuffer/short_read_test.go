package bitbuffer_test

import (
	"errors"
	"testing"

	"github.com/thebagchi/asn1c-go/lib/bitbuffer"
)

// _ShortRow is one row of TestRegression_P25ShortRead: the fields written, the widths read
// before the short read, the short read, and the read that must still work after it.
type _ShortRow struct {
	name   string
	fields []*_PeelField
	before []uint8
	short  uint8
	retry  *_PeelField
}

// TestRegression_P25ShortRead guards review P25: a Read that fails with ErrShortBuffer must
// leave the stream where it was. NumRead and Len stay, and the next Read sees the same bits.
// The rows cover the chunk loop (one byte crossing, and a read that needs two), the peel of a
// wide field, an aligned read after a full byte, and an aligned read that runs past the end.
//
// Revisions:
//   - 2026-10-21 12:30: initial creation (review P25)
//   - 2026-10-21 12:44: the row chunk_two_crossings, a read that runs short after its first
//     byte crossing
func TestRegression_P25ShortRead(t *testing.T) {
	rows := []*_ShortRow{
		{
			name: "chunk",
			fields: []*_PeelField{
				{
					width: 3,
					value: 7,
				},
				{
					width: 5,
					value: 0x15,
				},
			},
			before: []uint8{
				3,
			},
			short: 16,
			retry: &_PeelField{
				width: 5,
				value: 0x15,
			},
		},
		{
			name: "peel",
			fields: []*_PeelField{
				{
					width: 3,
					value: 7,
				},
				{
					width: 13,
					value: 0x1ABC,
				},
			},
			before: []uint8{
				3,
			},
			short: 32,
			retry: &_PeelField{
				width: 13,
				value: 0x1ABC,
			},
		},
		{
			name: "chunk_two_crossings",
			fields: []*_PeelField{
				{
					width: 3,
					value: 7,
				},
				{
					width: 13,
					value: 0x1ABC,
				},
			},
			before: []uint8{
				3,
			},
			short: 20,
			retry: &_PeelField{
				width: 13,
				value: 0x1ABC,
			},
		},
		{
			name: "full_byte",
			fields: []*_PeelField{
				{
					width: 8,
					value: 0xAB,
				},
			},
			before: []uint8{
				8,
			},
			short: 8,
		},
		{
			name: "aligned_past_end",
			fields: []*_PeelField{
				{
					width: 8,
					value: 0xAB,
				},
				{
					width: 8,
					value: 0xCD,
				},
			},
			before: []uint8{
				8,
			},
			short: 16,
			retry: &_PeelField{
				width: 8,
				value: 0xCD,
			},
		},
	}

	for _, row := range rows {
		t.Run(
			row.name,
			func(t *testing.T) {
				_CheckShortRead(
					t,
					row,
				)
			},
		)
	}
}

// _CheckShortRead writes the fields of a row, reads the bits before the short read, and makes
// sure the short read changes neither NumRead nor Len, and that the retry still reads.
//
// Revisions:
//   - 2026-10-21 12:30: initial creation (review P25)
func _CheckShortRead(
	t *testing.T,
	row *_ShortRow,
) {
	t.Helper()

	writer := bitbuffer.CreateWriter()
	for _, field := range row.fields {
		if err := writer.Write(
			field.width,
			field.value,
		); err != nil {
			t.Fatal(err)
		}
	}

	reader := bitbuffer.CreateReader(writer.Bytes())
	for _, width := range row.before {
		if _, err := reader.Read(width); err != nil {
			t.Fatal(err)
		}
	}

	var (
		read = reader.NumRead()
		size = reader.Len()

		_, err = reader.Read(row.short)
	)
	if !errors.Is(
		err,
		bitbuffer.ErrShortBuffer,
	) {
		t.Fatalf(
			"Read(%d) = %v, want ErrShortBuffer",
			row.short,
			err,
		)
	}

	if reader.NumRead() != read || reader.Len() != size {
		t.Fatalf(
			"after the short read: NumRead %d, Len %d; want %d, %d",
			reader.NumRead(),
			reader.Len(),
			read,
			size,
		)
	}

	if row.retry == nil {
		return
	}

	value, err := reader.Read(row.retry.width)
	if err != nil || value != row.retry.value {
		t.Fatalf(
			"retry Read(%d) = %x, %v; want %x",
			row.retry.width,
			value,
			err,
			row.retry.value,
		)
	}
}
