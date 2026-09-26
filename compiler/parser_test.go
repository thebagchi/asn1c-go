package compiler_test

import (
	"testing"

	"github.com/thebagchi/asn1c-go/compiler"
)

// TestRemoveBlockComment checks RemoveBlockComment. What it is really
// checking is the nesting X.680 12.6.4 requires, which is the one thing a
// regular expression could not do and the reason this walks the content.
//
// Revisions:
//   - 2026-09-26 09:14: initial creation
func TestRemoveBlockComment(t *testing.T) {
	cases := []struct {
		name string
		src  string
		want string
	}{
		{
			name: "a plain comment",
			src:  "A /* gone */ B",
			want: "A  B",
		},
		{
			name: "one comment inside another",
			src:  "A /* a /* b */ c */ B",
			want: "A  B",
		},
		{
			name: "three deep",
			src:  "A /* a /* b /* c */ b */ a */ B",
			want: "A  B",
		},
		{
			name: "two comments in a row are not one",
			src:  "A /* a */ B /* b */ C",
			want: "A  B  C",
		},
		{
			name: "a line comment is left alone",
			src:  "A -- note\nB",
			want: "A -- note\nB",
		},
		{
			name: "an unclosed comment runs to the end",
			src:  "A /* a /* b */ B",
			want: "A ",
		},
		{
			name: "content with no comment is unchanged",
			src:  "A ::= INTEGER",
			want: "A ::= INTEGER",
		},
	}

	for _, item := range cases {
		t.Run(item.name, func(t *testing.T) {
			got := string(compiler.RemoveBlockComment([]byte(item.src)))
			if got != item.want {
				t.Errorf("got %q, want %q", got, item.want)
			}
		})
	}
}
