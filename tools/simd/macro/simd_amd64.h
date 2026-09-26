// Macros for composing AVX2 kernels, and the worked example behind
// tools/simd/PLAN.md.
//
// Every macro says what it clobbers. Nothing checks that, which is exactly why
// the plan makes clobber assertions part of the test harness.

// BROADCAST_BYTE fills every lane of dst with the low byte of src.
//
// The move must be VMOVD and not MOVQ: a legacy SSE write to an XMM register
// inside a function full of VEX instructions costs an AVX-SSE transition
// penalty, which is golang/go#80835 and the reason the compiler's own simd
// output is slower than scalar code.
//
// Clobbers: tmp, dst.
#define BROADCAST_BYTE(src, tmp, dst) \
	VMOVD        src, tmp \
	VPBROADCASTB tmp, dst

// BYTE_SHL shifts every byte of v left by the count in cnt.
//
// AVX2 has no byte shift, so the shift is done sixteen bits at a time and mask
// clears the bits dragged across each byte boundary. mask must be
// broadcast(0xFF << cnt).
//
// Clobbers: v.
#define BYTE_SHL(cnt, mask, v) \
	VPSLLW cnt, v, v \
	VPAND  mask, v, v

// BYTE_SHR shifts every byte of v right by the count in cnt. mask must be
// broadcast(0xFF >> cnt).
//
// Clobbers: v.
#define BYTE_SHR(cnt, mask, v) \
	VPSRLW cnt, v, v \
	VPAND  mask, v, v

// RET_VEC returns from a function that has touched a YMM register.
//
// Leaving the upper halves dirty stalls the next SSE instruction anywhere in
// the process, so this exists so the VZEROUPPER cannot be forgotten.
#define RET_VEC \
	VZEROUPPER \
	RET
