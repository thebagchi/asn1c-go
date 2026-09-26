//go:build amd64

package macro

// _ShiftBlocks is implemented in shift_amd64.s, composed from the macros in
// simd_amd64.h and loop_amd64.h.
//
// len(src) must be at least len(dst)+1, and len(dst) a multiple of SHIFT_BLOCK.
//
//go:noescape
func _ShiftBlocks(dst, src []byte, free, used uint8)
