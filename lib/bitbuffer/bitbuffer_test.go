package bitbuffer

import (
	"bytes"
	"fmt"
	"testing"
)

func TestBitBuffer(t *testing.T) {
	w := CreateWriter()

	// Initial state
	if w.NumWritten() != 0 {
		t.Errorf("initial written should be 0, got %d", w.NumWritten())
	}
	if w.offset != 0 {
		t.Errorf("initial offset should be 0, got %d", w.offset)
	}

	// Write 16 bits of 0
	for i := range 16 {
		err := w.Write(1, 0)
		if err != nil {
			t.Fatalf("Write %d failed: %v", i+1, err)
		}
	}
	if w.NumWritten() != 16 {
		t.Errorf("after 16 writes, written should be 16, got %d", w.NumWritten())
	}
	if w.offset != 8 {
		t.Errorf("after 16 writes, offset should be 8, got %d", w.offset)
	}

	// WriteBytes([]byte{0x00})
	err := w.WriteBytes([]byte{0x00})
	if err != nil {
		t.Fatalf("WriteBytes failed: %v", err)
	}
	if w.NumWritten() != 24 {
		t.Errorf("after WriteBytes, written should be 24, got %d", w.NumWritten())
	}
	if w.offset != 8 {
		t.Errorf("after WriteBytes, offset should be 8, got %d", w.offset)
	}

	// Test Align() when offset == 8
	err = w.Align()
	if err != nil {
		t.Fatalf("Align failed: %v", err)
	}
	// Since offset was 8, Align does nothing
	if w.NumWritten() != 24 {
		t.Errorf("after Align, written should still be 24, got %d", w.NumWritten())
	}
	if w.offset != 8 {
		t.Errorf("after Align, offset should still be 8, got %d", w.offset)
	}

	// Try writing after Align
	err = w.Write(1, 1)
	if err != nil {
		t.Fatalf("Write after Align failed: %v", err)
	}
	if w.NumWritten() != 25 {
		t.Errorf("after writing bit, written should be 25, got %d", w.NumWritten())
	}
	if w.offset != 1 {
		t.Errorf("after writing bit, offset should be 1, got %d", w.offset)
	}

	// Check the buffer content
	bytes := w.Bytes()
	expected := []byte{0x00, 0x00, 0x00, 0x80}
	if len(bytes) != len(expected) {
		t.Errorf("bytes length should be %d, got %d", len(expected), len(bytes))
	} else {
		for i := range expected {
			if bytes[i] != expected[i] {
				t.Errorf("bytes[%d] should be 0x%02x, got 0x%02x", i, expected[i], bytes[i])
			}
		}
	}
}

func TestWriteReadBits(t *testing.T) {
	bits := make([]uint8, 64)
	for i := range bits {
		bits[i] = uint8(i + 1)
	}

	{
		w := CreateWriter()
		// Write 1 to 64 bits with values 1 to 64
		for _, bit := range bits {
			var (
				value = uint64(bit)
				err   = w.Write(bit, value)
			)
			if err != nil {
				t.Fatalf("Write %d bits with value %d failed: %v", bit, value, err)
			}
		}

		// Create reader from the written data
		r := CreateReader(w.Bytes())
		// Read back and validate
		for _, bit := range bits {
			var (
				expected    = uint64(bit)
				actual, err = r.Read(bit)
			)
			if err != nil {
				t.Fatalf("Read %d bits failed: %v", bit, err)
			}
			t.Logf("Bits: %d, Expected: %d, Actual: %d", bit, expected, actual)
			if actual != expected {
				t.Errorf("Read %d bits: expected %d, got %d", bit, expected, actual)
			}
		}
		if w.NumWritten() != 2080 {
			t.Errorf("Total written bits: expected 2080, got %d", w.NumWritten())
		}
		if r.NumRead() != 2080 {
			t.Errorf("Total read bits: expected 2080, got %d", r.NumRead())
		}
	}

	{
		w := CreateWriter()
		// Write 1 to 64 bits with value 0
		for _, bit := range bits {
			var (
				value = uint64(0)
				err   = w.Write(bit, value)
			)
			if err != nil {
				t.Fatalf("Write %d bits with value %d failed: %v", bit, value, err)
			}
		}

		// Create reader from the written data
		r := CreateReader(w.Bytes())
		// Read back and validate
		for _, bit := range bits {
			var (
				expected    = uint64(0)
				actual, err = r.Read(bit)
			)
			if err != nil {
				t.Fatalf("Read %d bits failed: %v", bit, err)
			}
			t.Logf("Bits: %d, Expected: %d, Actual: %d", bit, expected, actual)
			if actual != expected {
				t.Errorf("Read %d bits: expected %d, got %d", bit, expected, actual)
			}
		}
		if w.NumWritten() != 2080 {
			t.Errorf("Total written bits: expected 2080, got %d", w.NumWritten())
		}
		if r.NumRead() != 2080 {
			t.Errorf("Total read bits: expected 2080, got %d", r.NumRead())
		}
	}

	{
		w := CreateWriter()
		// Write 1 to 64 bits with max value for each bit count
		for _, bit := range bits {
			var (
				value = uint64((1 << bit) - 1)
				err   = w.Write(bit, value)
			)
			if err != nil {
				t.Fatalf("Write %d bits with value %d failed: %v", bit, value, err)
			}
		}

		// Create reader from the written data
		r := CreateReader(w.Bytes())
		// Read back and validate
		for _, bit := range bits {
			var (
				expected    = uint64((1 << bit) - 1)
				actual, err = r.Read(bit)
			)
			if err != nil {
				t.Fatalf("Read %d bits failed: %v", bit, err)
			}
			t.Logf("Bits: %d, Expected: %d, Actual: %d", bit, expected, actual)
			if actual != expected {
				t.Errorf("Read %d bits: expected %d, got %d", bit, expected, actual)
			}
		}
		if w.NumWritten() != 2080 {
			t.Errorf("Total written bits: expected 2080, got %d", w.NumWritten())
		}
		if r.NumRead() != 2080 {
			t.Errorf("Total read bits: expected 2080, got %d", r.NumRead())
		}
	}

	{
		w := CreateWriter()
		// Write 1 to 64 bits with values 1 to 64
		for _, bit := range bits {
			var (
				value = uint64(bit)
				err   = w.Write(bit, value)
			)
			if err != nil {
				t.Fatalf("Write %d bits with value %d failed: %v", bit, value, err)
			}
			var (
				length = (bit + 3) / 4
				data   = fmt.Sprintf("%0*x", length, value)
			)
			err = w.WriteBytes([]byte(data))
			if err != nil {
				t.Fatalf("WriteBytes failed: %v", err)
			}
		}

		// Create reader from the written data
		r := CreateReader(w.Bytes())
		// Read back and validate
		for _, bit := range bits {
			var (
				expected    = uint64(bit)
				actual, err = r.Read(bit)
			)
			if err != nil {
				t.Fatalf("Read %d bits failed: %v", bit, err)
			}
			t.Logf("Bits: %d, Expected: %d, Actual: %d", bit, expected, actual)
			if actual != expected {
				t.Errorf("Read %d bits: expected %d, got %d", bit, expected, actual)
			}
			var (
				length = (bit + 3) / 4
				data   = fmt.Appendf(nil, "%0*x", length, expected)
			)
			content, err := r.ReadBytes(int(length))
			if err != nil {
				t.Fatalf("ReadBytes failed: %v", err)
			}
			if !bytes.Equal(content, data) {
				t.Errorf("ReadBytes: expected %v, got %v", data, content)
			}
		}
		if w.NumWritten() != 6432 {
			t.Errorf("Total written bits: expected 6432, got %d", w.NumWritten())
		}
		if r.NumRead() != 6432 {
			t.Errorf("Total read bits: expected 6432, got %d", r.NumRead())
		}
	}

	{
		w := CreateWriter()
		// Write 1 to 64 bits with value 0 and hex bytes
		for _, bit := range bits {
			var (
				value = uint64(0)
				err   = w.Write(bit, value)
			)
			if err != nil {
				t.Fatalf("Write %d bits with value %d failed: %v", bit, value, err)
			}
			var (
				length = (bit + 3) / 4
				data   = fmt.Sprintf("%0*x", length, value)
			)
			err = w.WriteBytes([]byte(data))
			if err != nil {
				t.Fatalf("WriteBytes failed: %v", err)
			}
		}

		// Create reader from the written data
		r := CreateReader(w.Bytes())
		// Read back and validate
		for _, bit := range bits {
			var (
				expected    = uint64(0)
				actual, err = r.Read(bit)
			)
			if err != nil {
				t.Fatalf("Read %d bits failed: %v", bit, err)
			}
			t.Logf("Bits: %d, Expected: %d, Actual: %d", bit, expected, actual)
			if actual != expected {
				t.Errorf("Read %d bits: expected %d, got %d", bit, expected, actual)
			}
			var (
				length = (bit + 3) / 4
				data   = fmt.Appendf(nil, "%0*x", length, expected)
			)
			content, err := r.ReadBytes(int(length))
			if err != nil {
				t.Fatalf("ReadBytes failed: %v", err)
			}
			if !bytes.Equal(content, data) {
				t.Errorf("ReadBytes: expected %v, got %v", data, content)
			}
		}
		if w.NumWritten() != 6432 {
			t.Errorf("Total written bits: expected 6432, got %d", w.NumWritten())
		}
		if r.NumRead() != 6432 {
			t.Errorf("Total read bits: expected 6432, got %d", r.NumRead())
		}
	}

	{
		w := CreateWriter()
		// Write 1 to 64 bits with max value and hex bytes
		for _, bit := range bits {
			var (
				value = uint64(1<<bit) - 1
				err   = w.Write(bit, value)
			)
			if err != nil {
				t.Fatalf("Write %d bits with value %d failed: %v", bit, value, err)
			}
			var (
				length = (bit + 3) / 4
				data   = fmt.Sprintf("%0*x", length, value)
			)
			err = w.WriteBytes([]byte(data))
			if err != nil {
				t.Fatalf("WriteBytes failed: %v", err)
			}
		}

		// Create reader from the written data
		r := CreateReader(w.Bytes())
		// Read back and validate
		for _, bit := range bits {
			var (
				expected    = uint64(1<<bit) - 1
				actual, err = r.Read(bit)
			)
			if err != nil {
				t.Fatalf("Read %d bits failed: %v", bit, err)
			}
			t.Logf("Bits: %d, Expected: %d, Actual: %d", bit, expected, actual)
			if actual != expected {
				t.Errorf("Read %d bits: expected %d, got %d", bit, expected, actual)
			}
			var (
				length = (bit + 3) / 4
				data   = fmt.Appendf(nil, "%0*x", length, expected)
			)
			content, err := r.ReadBytes(int(length))
			if err != nil {
				t.Fatalf("ReadBytes failed: %v", err)
			}
			if !bytes.Equal(content, data) {
				t.Errorf("ReadBytes: expected %v, got %v", data, content)
			}
		}
		if w.NumWritten() != 6432 {
			t.Errorf("Total written bits: expected 6432, got %d", w.NumWritten())
		}
		if r.NumRead() != 6432 {
			t.Errorf("Total read bits: expected 6432, got %d", r.NumRead())
		}
	}
}

func TestHex(t *testing.T) {
	bits := make([]uint8, 64)
	for i := range bits {
		bits[i] = uint8(i + 1)
	}
	{
		for _, bit := range bits {
			var (
				value  = uint64(bit)
				length = (bit + 3) / 4
				data   = fmt.Appendf(nil, "%0*x", length, value)
			)
			fmt.Println(string(data))
		}
	}
}
