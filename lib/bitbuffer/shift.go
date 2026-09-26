package bitbuffer

import (
	"encoding/binary"
)

// BLOCK_GO is how many bytes the pure-Go shift handles per iteration: one word.
// The names are what the tables give the kernels, one per instruction set.
const (
	BLOCK_GO    = UINT64_BYTES
	NAME_GO     = "Go"
	NAME_SSE2   = "SSE2"
	NAME_AVX2   = "AVX2"
	NAME_AVX512 = "AVX512"
)

// _Kernel is one implementation of the mid-byte bulk shift: the code, how many
// bytes it handles per iteration, and whether this machine can run it.
//
// The pure-Go implementation is a kernel like any other, not a fallback: it is
// in the table on every architecture, the tests compare every kernel against
// the same reference through this one interface, and on an architecture with
// no assembly it is simply the only entry.
type _Kernel struct {
	name  string
	block int
	have  bool
	run   func(dst, src []byte, left, right uint8)
}

// The kernels, narrowest first with Go leading, and the one chosen. Everything
// here is resolved once at start-up rather than on the path that uses it;
// _ShiftKernels is what each architecture contributes.
var (
	SHIFT_GO = &_Kernel{
		name:  NAME_GO,
		block: BLOCK_GO,
		have:  true,
		run:   _ShiftBlocksGo,
	}
	SHIFT_KERNELS = _ShiftKernels()
	SHIFT_KERNEL  = _Select(SHIFT_KERNELS)
)

// Name says which instruction set the kernel is built on, or "Go".
//
// Revisions:
//   - 2026-09-23 03:58: initial creation
func (k *_Kernel) Name() string {
	return k.name
}

// Block is how many bytes the kernel handles per iteration, and so the multiple
// dst must be sized to.
//
// Revisions:
//   - 2026-09-23 03:58: initial creation
func (k *_Kernel) Block() int {
	return k.block
}

// Have reports whether this machine can run the kernel.
//
// Revisions:
//   - 2026-09-23 03:58: initial creation
func (k *_Kernel) Have() bool {
	return k.have
}

// Run writes dst[i] = src[i]<<left | src[i+1]>>right for every byte of dst.
//
// len(src) must be at least len(dst)+1, len(dst) a multiple of Block, and Have
// true; none of that is checked here, because the callers below guarantee it
// and this is the hot path. It is exported so a test can drive every kernel
// the machine supports rather than only the one selected.
//
// Revisions:
//   - 2026-09-23 03:58: initial creation
func (k *_Kernel) Run(dst, src []byte, left, right uint8) {
	k.run(dst, src, left, right)
}

// _ShiftBulk writes as much of out as the selected kernel can, and returns how
// many bytes of it were filled; zero means the caller does all the work.
//
// out[0] is the byte that carries bits from the partial byte already in the
// buffer, which the kernel cannot see, so it is written here.
//
// Revisions:
//   - 2026-09-22 09:12: initial creation
//   - 2026-09-23 03:58: runs whichever kernel was selected at start-up rather
//     than the AVX2 one alone
//   - 2026-09-23 06:50: calls the kernel by name, so a caller's stack buffer
//     is not moved to the heap on its way through WriteBytes
//   - 2026-09-24 01:40: portable, now that every architecture has a kernel
func _ShiftBulk(out, data []byte, used uint8, carry uint64) int {
	// The kernel reads one byte beyond each block, so the block count comes
	// off len(data)-1 rather than len(data).
	blocks := (len(data) - 1) / SHIFT_KERNEL.block * SHIFT_KERNEL.block
	if blocks == 0 {
		return 0
	}

	free := BITS_PER_BYTE - used
	out[0] = byte(carry<<free | uint64(data[0])>>used)

	_RunShift(out[1:1+blocks], data, free, used)

	return 1 + blocks
}

// _ReadBulk fills as much of dst as the selected kernel can with the bytes of
// src shifted left by used bits, and returns how many were filled.
//
// It is the mirror of _ShiftBulk with no carry to seed: a read starts at a
// byte boundary of dst, so every output byte is exactly one kernel lane.
// len(src) must be at least len(dst)+1, which the caller has already checked.
//
// Revisions:
//   - 2026-09-23 03:58: initial creation
//   - 2026-09-23 06:50: calls the kernel by name, for the reason _RunShift gives
//   - 2026-09-24 01:40: portable, now that every architecture has a kernel
func _ReadBulk(dst, src []byte, used uint8) int {
	blocks := len(dst) / SHIFT_KERNEL.block * SHIFT_KERNEL.block
	if blocks == 0 {
		return 0
	}

	_RunShift(dst[:blocks], src, used, BITS_PER_BYTE-used)

	return blocks
}

// _ShiftBlocksGo is the shift written in Go, a word at a time.
//
// Eight source bytes read as a big-endian word and shifted left move each
// byte's top bits into the byte before it, which is what the shift means; the
// byte after the word supplies the last byte's low bits.
//
// Revisions:
//   - 2026-09-24 01:40: initial creation, the word loop of _ReadShifted as a
//     kernel in the table
func _ShiftBlocksGo(dst, src []byte, left, right uint8) {
	for idx := 0; idx < len(dst); idx += BLOCK_GO {
		var (
			word = binary.BigEndian.Uint64(src[idx:])
			next = uint64(src[idx+BLOCK_GO])
		)

		binary.BigEndian.PutUint64(dst[idx:], word<<left|next>>right)
	}
}

// _Select returns the widest kernel the machine supports.
//
// Widest is a policy, not a measurement. On some processors a ZMM instruction
// lowers the clock for a while afterwards, and for short buffers that can cost
// more than the extra lanes save; the benchmarks in the tree are what would
// show it, on hardware that has AVX-512 to show it on.
//
// Revisions:
//   - 2026-09-23 03:58: initial creation
func _Select(kernels []*_Kernel) *_Kernel {
	var (
		chosen *_Kernel
	)

	for _, kernel := range kernels {
		if kernel.have {
			chosen = kernel
		}
	}

	return chosen
}
