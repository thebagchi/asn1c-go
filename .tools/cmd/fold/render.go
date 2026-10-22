package main

import (
	"bytes"
	"fmt"
	"go/format"
	"sort"
)

// _Render applies edits to src and formats the result with gofmt.
// It returns nil when the result equals src.
//
// Revisions:
//   - 2026-10-19 10:30: initial creation
func _Render(
	path string,
	src []byte,
	edits []*_Edit,
) ([]byte, error) {
	out, err := format.Source(
		_Apply(
			src,
			edits,
		),
	)
	if err != nil {
		return nil, fmt.Errorf(
			"format %s: %w",
			path,
			err,
		)
	}

	if bytes.Equal(
		out,
		src,
	) {
		return nil, nil
	}

	return out, nil
}

// _Apply inserts each edit into src.
// Edits at one offset keep their order.
//
// Revisions:
//   - 2026-10-19 10:30: initial creation
func _Apply(
	src []byte,
	edits []*_Edit,
) []byte {
	sort.SliceStable(
		edits,
		func(
			left int,
			right int,
		) bool {
			return edits[left].at < edits[right].at
		},
	)

	var out bytes.Buffer

	last := 0

	for _, edit := range edits {
		out.Write(
			src[last:edit.at],
		)
		out.WriteString(
			edit.text,
		)

		last = edit.at
	}

	out.Write(
		src[last:],
	)

	return out.Bytes()
}
