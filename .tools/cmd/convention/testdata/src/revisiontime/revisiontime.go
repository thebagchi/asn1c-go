package revisiontime

// _Bare does a thing.
//
// Revisions:
//   - initial creation
func _Bare() { // want `error: revision:.*minute`
}

// _Right does a thing.
//
// Revisions:
//   - 2026-10-04 00:00: initial creation
func _Right() {
}
