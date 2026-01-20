// Package bitbuffer provides bit-level I/O for ASN.1 PER (Packed Encoding Rules).
//
// # Overview
//
// The Codec type manages streaming bit-level encoding and decoding with MSB-first
// bit ordering. It supports writing and reading arbitrary bit lengths (1-64 bits),
// byte-aligned bulk operations, and byte boundary alignment.
//
// # Key Features
//
//   - Fast paths for byte-aligned operations using encoding/binary.BigEndian
//   - Slow paths for general bit-packing/unpacking
//   - Dynamic buffer growth with exponential allocation strategy
//   - Counters for total bits written/read (uint64, ~18 exabyte capacity)
//   - Lazy buffer advancement strategy to minimize allocations
//   - MSB-first bit ordering (most significant bit first per PER spec)
//
// # Dependencies
//
// Uses only Go standard library:
//   - encoding/binary: for endianness-agnostic multi-byte operations
//   - slices: for efficient buffer growth (Go 1.21+)
//
// # Scope
//
// This package focuses on bit-level manipulation. Callers are responsible for
// higher-level ASN.1 semantics, type encoding, and constraint validation.
//
// # Thread Safety
//
// Codec is NOT thread-safe. Multiple goroutines must not access the same Codec
// instance concurrently without external synchronization (e.g., mutex). Each
// goroutine should use its own Codec instance, or callers must provide synchronization.
package bitbuffer

import (
	"encoding/binary"
	"errors"
	"fmt"
	"slices"
)

const (
	// ENABLE_TRACE controls whether trace output is printed
	ENABLE_TRACE = false

	// BITS_PER_BYTE is the number of bits in a byte
	BITS_PER_BYTE = 8

	// TMP_ARRAY_SIZE is the size of temporary arrays used for binary operations
	TMP_ARRAY_SIZE = 8
)

// InitialBufferSize is the initial capacity for the buffer in CreateWriter.
var InitialBufferSize = 64

// Codec manages a bit stream for encoding and decoding.
// Fields:
//
//	Buff: byte slice holding the encoded bit stream
//	offset: bit position in current byte (0-8)
//	  - offset=0: start of byte (no bits consumed from this byte)
//	  - offset=1-7: partial byte (1-7 bits consumed from this byte)
//	  - offset=8: end of byte (all 8 bits consumed, ready for next byte)
//	written: total number of bits written
//	read: total number of bits read
type Codec struct {
	Buff    []byte
	offset  uint8
	written uint64
	read    uint64
}

// Trace prints debug information about the codec state.
// Only prints if ENABLE_TRACE is true (compile-time constant).
// Parameters:
//   - event: "ENTER" or "EXIT" to mark function entry/exit
//   - function: name of the calling function (e.g., "Write", "Read")
//   - arguments: optional additional debug info (e.g., "bits=8 value=42")
//
// Output includes current buffer length, offset, and bit counters.
func (c *Codec) Trace(event, function, arguments string) {
	if !ENABLE_TRACE {
		return
	}
	state := fmt.Sprintf("[%s %s] len=%d offset=%d written=%d read=%d",
		event, function, len(c.Buff), c.offset, c.written, c.read)
	if arguments != "" {
		state = state + " --> " + arguments
	}
	println(state)
}

// CreateWriter creates a new Codec for writing.
// Initializes with an empty buffer and pre-allocates capacity (InitialBufferSize)
// to reduce early allocations. Use this to begin encoding a bit stream.
func CreateWriter() *Codec {
	return &Codec{
		Buff: make([]byte, 0, InitialBufferSize),
	}
}

// CreateReader creates a new Codec for reading from existing data.
// Note: Assumes data is byte-aligned (starts at bit offset 0).
// If data contains partial bytes at the start (from mid-byte), call Advance() first
// or manually set offset as needed. For PER, input data is typically byte-aligned.
func CreateReader(data []byte) *Codec {
	return &Codec{
		Buff:   data,
		offset: 0,
	}
}

// Len returns the number of complete bytes currently in the buffer.
// This is the length of the buffer, not the number of bits available.
// For bit-level precision, use NumRead() and NumWritten().
func (c *Codec) Len() int {
	return len(c.Buff)
}

// Cap returns the capacity of the underlying buffer.
// Useful for understanding allocated vs. used memory. Buffer may grow internally.
func (c *Codec) Cap() int {
	return cap(c.Buff)
}

// NumWritten returns the total number of bits written.
// Includes partial bytes. For example, writing 3 bits then 5 bits returns 8.
func (c *Codec) NumWritten() uint64 {
	return c.written
}

// NumRead returns the total number of bits read.
// Includes partial bytes. For example, reading 3 bits then 5 bits returns 8.
func (c *Codec) NumRead() uint64 {
	return c.read
}

// Bytes returns the encoded data trimmed to the exact number of bytes needed.
// Includes the partial final byte if written is not a multiple of 8.
// Warning: Callers must handle partial bytes. For PER encoding, the final partial
// byte should be padded with zeros by the encoder (e.g., call Align() before Bytes()).
func (c *Codec) Bytes() []byte {
	if c.written == 0 {
		return nil
	}
	return c.Buff
}

// String implements the fmt.Stringer interface for Codec.
// Prints the members of Codec for debugging: buffer length, offset, bits written/read.
// Useful for logging and troubleshooting encoder/decoder state.
func (c *Codec) String() string {
	return fmt.Sprintf("Codec{Buff: len=%d, offset: %d, written: %d, read: %d}",
		len(c.Buff), c.offset, c.written, c.read)
}

// grow ensures space for at least n more bytes.
// Uses exponential growth strategy: capacity = max(current_capacity * 2, needed_size).
// This ensures O(1) amortized time for buffer expansion.
// Employs Go's slices.Grow for efficient memory management (Go 1.21+).
//
// Implementation notes:
//   - Exponential allocation: Doubling capacity (or using requested size if larger)
//     guarantees O(1) amortized growth, preventing quadratic time for many appends.
//   - Mathematical property: Sum of 1 + 2 + 4 + 8 + ... + n = 2n - 1, ensuring
//     total allocations across all grows is O(n) for n bytes written total.
//   - slices.Grow: Leverages Go stdlib (1.21+) for platform-optimal memory copying,
//     reducing code complexity and ensuring portability across architectures.
//   - Boundary handling: Grows when current capacity < needed size, avoiding
//     unnecessary allocations while ensuring no reallocation on next Write.
func (c *Codec) grow(n int) {
	if ENABLE_TRACE {
		c.Trace("ENTER", "grow", fmt.Sprintf("n=%d", n))
		defer c.Trace("EXIT", "grow", "")
	}
	if cap(c.Buff) < len(c.Buff)+n {
		capacity := max(cap(c.Buff)*2, len(c.Buff)+n)
		c.Buff = slices.Grow(c.Buff, capacity-len(c.Buff))
	}
	c.Buff = c.Buff[:len(c.Buff)+n]
}

// incrementRead increments the bits read counter.
// Uses uint64 for maximum capacity (~1.84e19 bits, or ~18 exabytes).
// Overflow is unrealistic in practice.
//
// Implementation notes:
//   - uint64 safety: Supports reading ~18 exabytes of data before overflow,
//     far exceeding practical requirements. For context: entire internet traffic
//     for a year is ~1 zettabyte = 1e21 bytes, so uint64 covers 18e18 bytes.
//   - Idempotent tracking: Always increments by actual bits read, ensuring
//     readCounter accurately reflects stream position. Supports debugging and
//     partial read recovery.
//   - Used by Read(), ReadBytes(), Advance() to maintain consistent state.
func (c *Codec) incrementRead(bits uint64) {
	c.read += bits
}

// incrementWrite increments the bits written counter.
// Uses uint64 for maximum capacity (~1.84e19 bits, or ~18 exabytes).
// Overflow is unrealistic in practice.
//
// Implementation notes:
//   - uint64 safety: Supports writing ~18 exabytes of data before overflow,
//     far exceeding practical requirements.
//   - Idempotent tracking: Always increments by actual bits written, ensuring
//     writeCounter accurately reflects stream position. Supports debugging.
//   - Used by Write(), WriteBytes(), Align() to maintain consistent state.
func (c *Codec) incrementWrite(bits uint64) {
	c.written += bits
}

// Write writes the least significant 'num' bits of value (1 ≤ num ≤ 64).
// num=0 returns error (per spec). Returns error if num > 64.
// MSB-first bit ordering: most significant bits written first.
//
// Implementation notes:
//   - Bit masking: (1 << num) - 1 extracts only the least significant 'num' bits
//   - Bit shifting: value << (64 - num) aligns bits to high end of uint64 for BigEndian write
//   - Lazy advancement: Sets offset==8 to signal next operation that byte is full,
//     avoiding immediate buffer advancement (O(n) operation)
//
// Fast path: O(1) amortized when byte-aligned (offset==0 or offset==8).
// Slow path: O(num) bit-by-bit packing when mid-byte (offset 1-7).
func (c *Codec) Write(num uint8, value uint64) error {
	if ENABLE_TRACE {
		c.Trace("ENTER", "Write", fmt.Sprintf("bits=%d value=%d", num, value))
		defer c.Trace("EXIT", "Write", "")
	}
	if num == 0 || num > 64 {
		return errors.New("bit count must be between 1 and 64")
	}

	// Mask the value to keep only the least significant 'num' bits,
	// setting higher bits to 0
	value = value & ((1 << num) - 1)

	// Fast path: writing at byte boundary (can write whole bytes).
	// offset==0 means start of byte; offset==8 means ready for new byte.
	if len(c.Buff) == 0 || c.offset == 8 {
		if c.offset == 8 {
			c.offset = 0 // Reset to start of new byte
		}

		nbytes := (int(num) + 7) >> 3 // = ceil(num/8)
		remainder := num & 7

		tmp := [TMP_ARRAY_SIZE]byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}
		binary.BigEndian.PutUint64(tmp[:], value<<(64-uint(num)))

		c.Buff = append(c.Buff, tmp[:nbytes]...)

		// Set offset for next operation: remainder bits consumed (1-7) or 8 if full byte.
		c.offset = uint8(remainder)
		if c.offset == 0 {
			c.offset = 8 // Full byte consumed; mark as ready for next byte
		}
		c.incrementWrite(uint64(num))
		return nil
	}

	pending := num
	for pending > 0 {
		// If current byte is full (offset==8) or buffer empty, allocate new byte.
		if c.offset == 8 || len(c.Buff) == 0 {
			c.grow(1)
			c.offset = 0 // Start fresh byte
		}

		var (
			available = uint8(8 - c.offset) // Bits available in current byte
			nbits     = min(pending, available)
			remaining = pending - nbits
			chunk     = uint8(value>>remaining) & ((1 << nbits) - 1)
			shift     = available - nbits
			pos       = len(c.Buff) - 1
		)

		c.Buff[pos] = c.Buff[pos] | (chunk << shift)
		c.offset = c.offset + nbits // Advance offset within byte (will reach 8)
		pending = pending - nbits
	}

	c.incrementWrite(uint64(num))
	return nil
}

// Read reads the next num bits from the bit stream, returning them as a uint64.
// num=0 returns 0 without error. num > 64 returns error.
// MSB-first bit ordering: most significant bits read first.
// Returns error if insufficient data available.
//
// Implementation notes:
//   - Lazy buffer advancement: offset==8 signals "advance to next byte on next Read()",
//     deferring expensive buffer slice operation. This reduces unnecessary slicing and
//     improves cache locality for sequential reads.
//   - Fast path (byte-aligned): Uses binary.BigEndian.Uint64() with right-shift
//     to extract multi-byte values efficiently in O(1) amortized time.
//   - Slow path (mid-byte): Iterates through bits using shift/mask operations to
//     handle reads that span byte boundaries or start mid-byte.
//   - Offset state machine: Cycles through 0,1,2,...,7,8 with 8 marking "next byte ready".
//   - Each read increments readCounter via incrementRead() for tracing/debugging.
func (c *Codec) Read(num uint8) (uint64, error) {
	if ENABLE_TRACE {
		c.Trace("ENTER", "Read", fmt.Sprintf("num=%d", num))
		defer c.Trace("EXIT", "Read", "")
	}
	if num == 0 {
		return 0, nil
	}
	if num > 64 {
		return 0, errors.New("bit count must be between 1 and 64")
	}

	if c.Len() == 0 {
		return 0, errors.New("no more data")
	}

	// Fast path: reading at byte boundary (offset==0 or offset==8 ready for next byte).
	if len(c.Buff) == 0 || c.offset == 8 {
		// If at end of current byte (offset==8), advance to next byte.
		if c.offset == 8 {
			if len(c.Buff) == 0 {
				return 0, errors.New("unexpected end of data")
			}
			c.Buff = c.Buff[1:] // Consume the byte marked by offset==8
			c.offset = 0        // Start fresh at new byte
			if len(c.Buff) == 0 {
				return 0, errors.New("unexpected end of data")
			}
		}

		nbytes := (int(num) + 7) >> 3 // = ceil(num/8)
		if nbytes > 0 {
			if len(c.Buff) < nbytes {
				return 0, errors.New("insufficient data")
			}
			tmp := [TMP_ARRAY_SIZE]byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}
			copy(tmp[0:nbytes], c.Buff[:nbytes])
			var (
				result    = binary.BigEndian.Uint64(tmp[:]) >> (64 - num)
				remainder = num % 8
			)
			// Lazy advancement strategy: keep one extra byte in buffer and mark with offset=8
			// to signal next read cycle. Slow path detects offset==8 and advances.
			// If remainder>0: we consumed nbytes-1 full bytes + partial; keep partial byte.
			// If remainder=0: we consumed nbytes full bytes; keep last byte, marked by offset=8.
			c.Buff = c.Buff[nbytes-1:]
			if remainder == 0 {
				c.offset = 8
			} else {
				c.offset = remainder
			}

			c.incrementRead(uint64(num))
			return result, nil
		}
	}

	var (
		result  uint64
		pending = num
	)

	for pending > 0 {
		// If current byte is full (offset==8), advance to next byte.
		if c.offset == 8 {
			c.Buff = c.Buff[1:] // Consume byte marked by offset==8
			c.offset = 0        // Start fresh at new byte
			if len(c.Buff) == 0 {
				return 0, errors.New("unexpected end of data")
			}
		}

		var (
			remaining = uint8(8 - c.offset) // Bits left in current byte
			reading   = min(pending, remaining)
			mask      = uint8((1 << reading) - 1)
			shift     = remaining - reading
			bits      = uint64((c.Buff[0] >> shift) & mask)
		)

		result = (result << reading) | bits

		c.offset = c.offset + reading // Advance offset within byte (0 to 8)
		pending = pending - reading
	}

	c.incrementRead(uint64(num))
	return result, nil
}

// WriteBytes writes full octets continuing from the current bit offset.
// Equivalent to repeated Write(8, uint64(b)) for each byte.
// Does NOT force alignment — caller must Align() if required
// (e.g., APER octet string contents).
// Fast path: if byte-aligned (offset==0 or offset==8), appends directly (O(1) amortized).
// Slow path: if mid-byte (offset 1-7), packs each byte bit-by-bit via Write().
func (c *Codec) WriteBytes(data []byte) error {
	if ENABLE_TRACE {
		c.Trace("ENTER", "WriteBytes", fmt.Sprintf("len(data)=%d", len(data)))
		defer c.Trace("EXIT", "WriteBytes", "")
	}
	if len(data) == 0 {
		return nil
	}

	// Fast path: already byte-aligned (offset == 0) or at byte
	// boundary (offset == 8)
	if len(c.Buff) == 0 || c.offset == 8 {
		c.Buff = append(c.Buff, data...)
		c.incrementWrite(uint64(len(data) * 8))
		c.offset = 8
		return nil
	}

	// Slow path: pack each byte using general Write
	for _, b := range data {
		if err := c.Write(8, uint64(b)); err != nil {
			return err
		}
	}
	return nil
}

// ReadBytes reads exactly n full octets (bytes) from the bit stream.
// Continues from current bit offset. Equivalent to calling Read(8) n times.
// Returns error if insufficient data available (error message: "insufficient data").
// Fast path: if byte-aligned (offset==0 or offset==8), copies directly (O(n) with minimal overhead).
// Slow path: if mid-byte (offset 1-7), unpacks each byte bit-by-bit via Read().
func (c *Codec) ReadBytes(n int) ([]byte, error) {
	if ENABLE_TRACE {
		c.Trace("ENTER", "ReadBytes", fmt.Sprintf("n=%d", n))
		defer c.Trace("EXIT", "ReadBytes", "")
	}
	if n < 0 {
		return nil, errors.New("negative byte count")
	}
	if n == 0 {
		return []byte{}, nil
	}

	// Fast path: already byte-aligned (offset == 0) or at byte
	// boundary (offset == 8)
	if c.offset == 0 || c.offset == 8 {
		// If at end of byte, advance to next byte first
		if c.offset == 8 {
			if len(c.Buff) == 0 {
				return nil, errors.New("insufficient data")
			}
			c.Buff = c.Buff[1:]
			c.offset = 0
		}

		if len(c.Buff) < n {
			return nil, errors.New("insufficient data")
		}
		result := make([]byte, n)
		copy(result, c.Buff[:n])
		c.Buff = c.Buff[n:]
		c.incrementRead(uint64(n * 8))
		return result, nil
	}

	// Slow path: read each byte using general Read
	result := make([]byte, n)
	for i := range result {
		val, err := c.Read(8)
		if err != nil {
			return nil, err
		}
		result[i] = uint8(val)
	}
	return result, nil
}

// Align advances to the next byte boundary by appending a new byte if necessary.
// Unused bits in the previous byte remain zero.
// Used explicitly by the PER encoder when alignment is required (e.g., APER).
// If already aligned (offset==0 or offset==8), does nothing.
// Does NOT append a new byte if offset==8; next Write will handle that.
//
// Implementation notes:
//   - Lazy byte creation: Doesn't immediately append a new byte when offset==0-7.
//     Instead, sets offset==8 to signal next Write() to create the new byte.
//     This reduces allocations and keeps Align() a simple O(1) operation.
//   - Zero-padding: Unused bits are already zero in the last byte, so no need to
//     explicitly zero them; just mark the byte as full via offset==8.
//   - Idempotent: Can call multiple times without side effects when offset==0 or 8.
func (c *Codec) Align() error {
	if ENABLE_TRACE {
		c.Trace("ENTER", "Align", "")
		defer c.Trace("EXIT", "Align", "")
	}
	if c.offset > 0 && c.offset < 8 {
		// Partial byte - pad with zeros (which already exists) and move to next byte
		// Set offset to 8 to indicate byte is full; next Write will handle creating new byte
		c.incrementWrite(uint64(8 - c.offset))
		c.offset = 8
	}
	// If offset == 8 or offset == 0, already aligned, do nothing
	return nil
}

// Advance skips remaining bits to reach the next byte boundary (for reading).
// Sets offset to 8 to indicate we're at a byte boundary.
// Buffer advancement is handled by Read() when it encounters offset == 8.
// This is the read counterpart to Align() for writing.
// Increments the read counter by the number of skipped bits (8 - offset).
//
// Implementation notes:
//   - Lazy buffer advancement: Doesn't immediately slice the buffer. Instead,
//     sets offset==8 to signal next Read() to perform the actual byte slice.
//     This defers expensive buffer operations and keeps Advance() O(1).
//   - Idempotent: Calling when already aligned (offset==0 or 8) is safe and
//     efficient (immediate return, no state change).
//   - Read counter tracking: Increments readCounter to account for skipped bits,
//     essential for tracing and ensuring readCounter stays synchronized with
//     actual bits consumed from the stream.
func (c *Codec) Advance() error {
	if ENABLE_TRACE {
		c.Trace("ENTER", "Advance", "")
		defer c.Trace("EXIT", "Advance", "")
	}
	if c.offset > 0 {
		c.incrementRead(uint64(8 - c.offset))
		c.offset = 8
	}
	// Buffer advancement will be triggered by subsequent Read() calls
	return nil
}
