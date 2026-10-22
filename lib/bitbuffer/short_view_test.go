package bitbuffer_test

import (
	"errors"
	"testing"

	"github.com/thebagchi/asn1c-go/lib/bitbuffer"
)

// _ViewRow is one row of TestRegression_P26ShortView: the bytes written, the bits read
// before the short view, the octets the view asks for, and the read that must still work.
type _ViewRow struct {
	name  string
	bytes []byte
	skip  uint8
	view  int
	retry *_PeelField
}

// TestRegression_P26ShortView guards review P26: a ReadView that fails with ErrShortBuffer
// must leave the stream where it was. After a whole byte the offset is 8, and the spent
// byte is still in the buffer; the view must not drop it before it knows the rest fits.
//
// Revisions:
//   - 2026-10-21 13:12: initial creation (review P26)
func TestRegression_P26ShortView(t *testing.T) {
	rows := []*_ViewRow{
		{
			name: "one_byte",
			bytes: []byte{
				0xAB,
			},
			skip: 8,
			view: 1,
		},
		{
			name: "past_end",
			bytes: []byte{
				0xAB,
				0xCD,
			},
			skip: 8,
			view: 4,
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
				_CheckShortView(
					t,
					row,
				)
			},
		)
	}
}

// _CheckShortView reads the skip bits, asks for the short view, and checks the place.
//
// Revisions:
//   - 2026-10-21 13:12: initial creation
func _CheckShortView(
	t *testing.T,
	row *_ViewRow,
) {
	t.Helper()

	reader := bitbuffer.CreateReader(row.bytes)
	if _, err := reader.Read(row.skip); err != nil {
		t.Fatal(err)
	}

	var (
		read = reader.NumRead()
		size = reader.Len()

		_, err = reader.ReadView(row.view)
	)
	if !errors.Is(
		err,
		bitbuffer.ErrShortBuffer,
	) {
		t.Fatalf(
			"ReadView(%d) = %v, want ErrShortBuffer",
			row.view,
			err,
		)
	}

	if reader.NumRead() != read || reader.Len() != size {
		t.Fatalf(
			"after the short view: NumRead %d, Len %d; want %d, %d",
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
