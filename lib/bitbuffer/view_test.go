package bitbuffer_test

import (
	"bytes"
	"errors"
	"testing"

	"github.com/thebagchi/asn1c-go/lib/bitbuffer"
)

// How much a caller asks Grow for, and how far the reads below look.
const (
	RESERVE   = 1000
	VIEW_SIZE = 16
	INPUT     = 40
)

// TestGrowReservesWithoutExtending checks that Grow changes capacity and
// nothing else: not the length, not the contents, and nothing at all for a
// request of zero or less.
//
// Revisions:
//   - 2026-09-23 07:40: initial creation
func TestGrowReservesWithoutExtending(t *testing.T) {
	t.Parallel()

	writer := bitbuffer.CreateWriter()

	if err := writer.WriteBytes(payload(VIEW_SIZE)); err != nil {
		t.Fatal(err)
	}

	var (
		length = writer.Len()
		before = append([]byte(nil), writer.Bytes()...)
	)

	writer.Grow(RESERVE)

	if writer.Len() != length {
		t.Errorf("Grow changed Len from %d to %d", length, writer.Len())
	}

	if writer.Cap() < length+RESERVE {
		t.Errorf("Cap is %d after Grow(%d) at Len %d", writer.Cap(), RESERVE, length)
	}

	if !bytes.Equal(writer.Bytes(), before) {
		t.Errorf("Grow changed the contents")
	}

	capacity := writer.Cap()

	writer.Grow(0)
	writer.Grow(-RESERVE)

	if writer.Cap() != capacity {
		t.Errorf("Grow of zero or less changed Cap from %d to %d", capacity, writer.Cap())
	}
}

// TestReadViewAliasesWhenAligned checks the contract ReadView states: a window
// onto the codec's buffer when the read is octet-aligned, a copy when it is
// not, and the same octets either way.
//
// Aliasing is checked by writing through the input after the view is taken.
// That is exactly what a caller must never do, which is why it is the right
// probe here: it is the only way to tell a view from a copy.
//
// Revisions:
//   - 2026-09-23 07:40: initial creation
func TestReadViewAliasesWhenAligned(t *testing.T) {
	t.Parallel()

	t.Run("aligned view", func(t *testing.T) {
		t.Parallel()

		var (
			data   = payload(INPUT)
			reader = bitbuffer.CreateReader(data)
		)

		view, err := reader.ReadView(VIEW_SIZE)
		if err != nil {
			t.Fatal(err)
		}

		if !bytes.Equal(view, data[:VIEW_SIZE]) {
			t.Fatalf("view = % x, want % x", view, data[:VIEW_SIZE])
		}

		data[0] ^= 0xFF

		if view[0] != data[0] {
			t.Errorf("an aligned view copied rather than aliased")
		}

		const WANT = VIEW_SIZE * bitbuffer.BITS_PER_BYTE

		if reader.NumRead() != WANT {
			t.Errorf("NumRead = %d, want %d", reader.NumRead(), WANT)
		}
	})

	t.Run("misaligned copy", func(t *testing.T) {
		t.Parallel()

		const (
			OFFSET = 3
			REST   = bitbuffer.BITS_PER_BYTE - OFFSET
		)

		var (
			data   = payload(INPUT)
			reader = bitbuffer.CreateReader(data)
		)

		if _, err := reader.Read(OFFSET); err != nil {
			t.Fatal(err)
		}

		view, err := reader.ReadView(VIEW_SIZE)
		if err != nil {
			t.Fatal(err)
		}

		// The shift written the slow obvious way, here rather than shared
		// with the kernel tests, which build on amd64 only.
		want := make([]byte, VIEW_SIZE)
		for idx := range want {
			want[idx] = data[idx]<<OFFSET | data[idx+1]>>REST
		}

		if !bytes.Equal(view, want) {
			t.Fatalf("view = % x, want % x", view, want)
		}

		data[0] ^= 0xFF

		if !bytes.Equal(view, want) {
			t.Errorf("a misaligned view aliased rather than copied")
		}
	})

	t.Run("short buffer", func(t *testing.T) {
		t.Parallel()

		reader := bitbuffer.CreateReader(payload(INPUT))

		_, err := reader.ReadView(INPUT + 1)
		if !errors.Is(err, bitbuffer.ErrShortBuffer) {
			t.Errorf("got %v, want ErrShortBuffer", err)
		}
	})

	t.Run("nothing", func(t *testing.T) {
		t.Parallel()

		reader := bitbuffer.CreateReader(payload(INPUT))

		view, err := reader.ReadView(0)
		if err != nil || len(view) != 0 {
			t.Errorf("ReadView(0) = % x, %v", view, err)
		}
	})
}
