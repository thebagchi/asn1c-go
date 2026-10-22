package revision

func _None() { // want `error: revision:.*fix: add a Revisions list whose first bullet is initial creation`
}

// _Wrong does a thing.
//
// Revisions:
//   - 2026-10-04 00:00: added a parameter
func _Wrong() { // want `error: revision:.*fix: change the first Revisions bullet so it contains initial creation`
}

// _Right does a thing.
//
// Revisions:
//   - 2026-10-04 00:00: initial creation
func _Right() {
}
