package fields

type _Gap struct {
	A int

	B int // want `error: fields:.*fix: delete the blank line or the comment between the fields`
}

type _Comment struct {
	A int
	// note
	B int // want `error: fields:.*fix: delete the blank line or the comment between the fields`
}

type _OK struct {
	A int
	B int
}
