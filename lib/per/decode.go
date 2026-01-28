package per

import "github.com/thebagchi/asn1c-go/lib/bitbuffer"

// Decoder represents a PER decoder
type Decoder struct {
	codec   *bitbuffer.Codec
	aligned bool
}

// NewDecoder creates a new PER decoder from encoded data
// aligned: true for APER, false for UPER
func NewDecoder(data []byte, aligned bool) *Decoder {
	return &Decoder{
		codec:   bitbuffer.CreateReader(data),
		aligned: aligned,
	}
}
