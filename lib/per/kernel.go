package per

// The names the tables give the kernels, one per instruction set.
const (
	NAME_GO   = "Go"
	NAME_SSE2 = "SSE2"
	NAME_AVX2 = "AVX2"
)

// _Kernel is one implementation of a text conversion, in both directions: the
// code, how much input each direction handles per iteration, and whether this
// machine can run it.
//
// Every conversion here has the same shape. Encoding turns bytes into
// characters and decoding turns characters back, each function taking a
// destination and a source and returning how much of the source it consumed -
// whole blocks only, and none past a block holding something outside the
// alphabet, so that the scalar code after it reports the error in the words it
// always used. The pure-Go implementation is a kernel like any other, not a
// fallback: it is in every table on every architecture, the tests compare each
// kernel against the same reference through this one interface, and on an
// architecture with no assembly it is simply the only entry.
//
// The chains in the *_amd64.go files - _PackNumeric, _EncodeHex and the rest -
// run the assembly kernels only, and each caller finishes with the Go kernel
// itself rather than the chain doing it. A function holding both an assembly
// call and the Go one is past what the compiler inlines, and for the
// hexadecimal and binary conversions that one extra call measured 7-15 % at
// 64 bytes; with the Go call in the caller, a one-kernel chain inlines away.
type _Kernel struct {
	name        string
	have        bool
	encodeBlock int
	decodeBlock int
	encode      func(dst, src []byte) int
	decode      func(dst, src []byte) int
}

// Name says which instruction set the kernel is built on, or "Go".
//
// Revisions:
//   - 2026-09-24 01:40: initial creation
func (k *_Kernel) Name() string {
	return k.name
}

// Have reports whether this machine can run the kernel.
//
// Revisions:
//   - 2026-09-24 01:40: initial creation
func (k *_Kernel) Have() bool {
	return k.have
}

// EncodeBlock is how much source Encode handles per iteration.
//
// Revisions:
//   - 2026-09-24 01:40: initial creation
func (k *_Kernel) EncodeBlock() int {
	return k.encodeBlock
}

// DecodeBlock is how much source Decode handles per iteration.
//
// Revisions:
//   - 2026-09-24 01:40: initial creation
func (k *_Kernel) DecodeBlock() int {
	return k.decodeBlock
}

// Encode converts src into dst and returns how much of src it consumed. It is
// exported so a test can drive every kernel the machine supports rather than
// only the one selected; the size dst must have is each conversion's own.
//
// Revisions:
//   - 2026-09-24 01:40: initial creation
func (k *_Kernel) Encode(dst, src []byte) int {
	return k.encode(dst, src)
}

// Decode converts src back into dst, on the same terms as Encode.
//
// Revisions:
//   - 2026-09-24 01:40: initial creation
func (k *_Kernel) Decode(dst, src []byte) int {
	return k.decode(dst, src)
}

// _Select returns the widest kernel the machine supports: the last in the
// table it can run, the tables being ordered narrowest first with Go leading.
//
// Revisions:
//   - 2026-09-24 01:40: initial creation
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
