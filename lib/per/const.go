package per

const (
	// MAX_CONSTRAINED_LENGTH is the maximum value for which a length determinant
	// can be encoded/decoded as a constrained whole number. Beyond this, it's unconstrained.
	// ITU-T X.691 Section 11.9.3.3 / 11.9.4.1
	MAX_CONSTRAINED_LENGTH = 65536 // 64K

	// FRAGMENT_SIZE is the size of each fragment for fragmented indefinite-length encoding.
	// Used when encoding/decoding lengths greater than 64K.
	// ITU-T X.691 Section 11.9.4.2
	FRAGMENT_SIZE = 16384 // 16K = 16 * 1024
)
