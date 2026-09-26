package builtin

// _DurationPresence is a DURATION type's preamble: one bit per OPTIONAL
// component, in the declaration order X.691 clause 19.2 writes them in.
//
// The two DURATION types carry the same components, so their preambles have the
// same shape even though the types that hold them differ.
type _DurationPresence struct {
	years    bool
	months   bool
	weeks    bool
	days     bool
	hours    bool
	minutes  bool
	seconds  bool
	fraction bool
}
