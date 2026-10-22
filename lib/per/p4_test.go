package per_test

import (
	"testing"

	"github.com/thebagchi/asn1c-go/lib/per"
)

// VECTOR_UNSIGNED, VECTOR_OID, VECTOR_RELATIVE_OID and VECTOR_IRI are the kind keys in
// testing.json of testing/unsigned.py, oid.py, relativeoid.py and iri.py. Each asks pycrate
// 0.8.1 and Erlang/OTP 29.1.1 for every expected octet in it.
const (
	VECTOR_UNSIGNED     = "unsigned"
	VECTOR_OID          = "oid"
	VECTOR_RELATIVE_OID = "relativeoid"
	VECTOR_IRI          = "iri"
)

// _P4Oracles is what each Phase 4 vector row says about its answers.
type _P4Oracles struct {
	Oracles   []string `json:"oracles"`
	Agree     bool     `json:"agree"`
	DecidedBy string   `json:"decided_by"`
	_Expected
}

// _CheckFramed writes a value between BOOLEAN fields and reads it back. The fields
// are true before the value and false, true, false after it. A decoder that stops
// one bit early or late, or that skips the wrong padding, reads a wrong BOOLEAN.
//
// Revisions:
//   - 2026-10-19 11:31: initial creation
func _CheckFramed(
	t *testing.T,
	aligned bool,
	write func(enc *per.Encoder) error,
	read func(dec *per.Decoder) error,
) {
	t.Helper()

	enc := ENCODERS[aligned]()

	if err := enc.EncodeBoolean(true); err != nil {
		t.Fatalf(
			"EncodeBoolean(prefix) = %v",
			err,
		)
	}

	if err := write(enc); err != nil {
		t.Fatalf(
			"encode = %v",
			err,
		)
	}

	for _, flag := range []bool{false, true, false} {
		if err := enc.EncodeBoolean(flag); err != nil {
			t.Fatalf(
				"EncodeBoolean(trailer) = %v",
				err,
			)
		}
	}

	var (
		dec = DECODERS[aligned](enc.Bytes())

		prefix, err = dec.DecodeBoolean()
	)
	if err != nil || !prefix {
		t.Fatalf(
			"DecodeBoolean(prefix) = %v, %v, want true",
			prefix,
			err,
		)
	}

	if err := read(dec); err != nil {
		t.Fatalf(
			"decode = %v",
			err,
		)
	}

	for index, want := range []bool{false, true, false} {
		got, err := dec.DecodeBoolean()
		if err != nil || got != want {
			t.Fatalf(
				"DecodeBoolean(trailer %d) = %v, %v, want %v",
				index,
				got,
				err,
				want,
			)
		}
	}
}
