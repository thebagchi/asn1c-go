package revisionindent

// _Flat does a thing.
//
// Revisions:
// - 2026-10-04 00:00: initial creation
func _Flat() { // want `error: revision:.*two spaces`
}

// _Later does a thing.
//
// Revisions:
//   - 2026-10-04 00:00: initial creation
//
// - 2026-10-21 16:21: add a later bullet
func _Later() { // want `error: revision:.*two spaces`
}

// _Right does a thing.
//
// Revisions:
//   - 2026-10-04 00:00: initial creation
func _Right() {
}
