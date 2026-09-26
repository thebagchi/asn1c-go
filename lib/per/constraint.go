package per

// Constraint is the PER-visible constraint on a type: the bounds it restricts
// values or lengths to, and whether an extension marker follows them.
//
// The three travel together because X.691 reads them together. Whether a value
// is in the extension root is decided by comparing it with the same bounds that
// would otherwise encode it, so a caller that had to pass them separately could
// pass a marker without the bounds that give it meaning.
//
// A nil *Constraint reads as Unconstrained, so a caller with nothing to say can
// say nothing.
type Constraint struct {
	lb  *int64
	ub  *int64
	ext bool
}

// Unconstrained returns the constraint of a type with no PER-visible bounds,
// such as INTEGER (MIN..MAX) or an OCTET STRING with no SIZE.
//
// Revisions:
//   - 2026-09-22 06:43: initial creation
func Unconstrained() *Constraint {
	return new(Constraint)
}

// Constrained returns the constraint of a type bounded at both ends, such as
// INTEGER (0..255) or OCTET STRING (SIZE(4..8)).
//
// Revisions:
//   - 2026-09-22 06:43: initial creation
func Constrained(lb, ub int64) *Constraint {
	return &Constraint{
		lb: &lb,
		ub: &ub,
	}
}

// SemiConstrained returns the constraint of a type bounded below only, such as
// INTEGER (0..MAX).
//
// Revisions:
//   - 2026-09-22 06:43: initial creation
func SemiConstrained(lb int64) *Constraint {
	return &Constraint{
		lb: &lb,
	}
}

// Bounded returns the constraint of a type bounded above only, such as
// OCTET STRING (SIZE(0..8)) written without its minimum.
//
// The two readings of a missing lower bound are both correct and this type
// carries both: a length takes it as zero, because X.691 clauses 16.4, 17.2 and
// 20.2 say an unstated minimum is zero, while an integer takes it as absent,
// because clause 13.2.4 makes an integer with no lower bound unconstrained.
//
// Revisions:
//   - 2026-09-22 06:43: initial creation
func Bounded(ub int64) *Constraint {
	return &Constraint{
		ub: &ub,
	}
}

// Extensible returns a copy of c whose type carries an extension marker, the
// "..." of INTEGER (0..999, ...).
//
// It copies rather than setting in place so a Constraint held in a package-level
// variable cannot be changed by a caller that only meant to derive one from it.
//
// Revisions:
//   - 2026-09-22 06:43: initial creation
func (c *Constraint) Extensible() *Constraint {
	if c == nil {
		return &Constraint{ext: true}
	}

	return &Constraint{
		lb:  c.lb,
		ub:  c.ub,
		ext: true,
	}
}

// Lower returns the lower bound, and whether the type has one.
//
// Revisions:
//   - 2026-09-22 06:43: initial creation
func (c *Constraint) Lower() (int64, bool) {
	if c == nil || c.lb == nil {
		return 0, false
	}

	return *c.lb, true
}

// Upper returns the upper bound, and whether the type has one.
//
// Revisions:
//   - 2026-09-22 06:43: initial creation
func (c *Constraint) Upper() (int64, bool) {
	if c == nil || c.ub == nil {
		return 0, false
	}

	return *c.ub, true
}

// HasExtension reports whether the type carries an extension marker.
//
// Revisions:
//   - 2026-09-22 06:43: initial creation
func (c *Constraint) HasExtension() bool {
	return c != nil && c.ext
}

// Fixed returns the single length every value of the type must have, and
// whether the type has one. X.691 clauses 16.9, 17.6 and 20.5 all turn on this
// case, where a length needs no determinant because it cannot vary.
//
// Revisions:
//   - 2026-09-22 06:43: initial creation
func (c *Constraint) Fixed() (uint64, bool) {
	upper, bounded := c.Upper()
	if !bounded || upper < 0 {
		return 0, false
	}

	if c._SizeLower() != uint64(upper) {
		return 0, false
	}

	return uint64(upper), true
}

// _SizeLower returns the lower bound to use when the constraint bounds a length
// rather than a value, which is zero when the type states no minimum.
//
// Revisions:
//   - 2026-09-22 06:43: initial creation
func (c *Constraint) _SizeLower() uint64 {
	lower, bounded := c.Lower()
	if !bounded || lower < 0 {
		return 0
	}

	return uint64(lower)
}

// _SizeUpper returns the upper bound to use when the constraint bounds a length,
// and whether the type states one.
//
// Revisions:
//   - 2026-09-22 06:43: initial creation
func (c *Constraint) _SizeUpper() (uint64, bool) {
	upper, bounded := c.Upper()
	if !bounded || upper < 0 {
		return 0, false
	}

	return uint64(upper), true
}

// _Covers reports whether value lies within the extension root, which is what
// decides the extension bit of clause 13.1 and the range check of clause 13.2.
//
// Revisions:
//   - 2026-09-22 06:43: initial creation
func (c *Constraint) _Covers(value int64) bool {
	if lower, bounded := c.Lower(); bounded && value < lower {
		return false
	}

	if upper, bounded := c.Upper(); bounded && value > upper {
		return false
	}

	return true
}

// _CoversLength reports whether a length lies within the extension root, reading
// the bounds as a length constraint.
//
// Revisions:
//   - 2026-09-22 06:43: initial creation
func (c *Constraint) _CoversLength(length uint64) bool {
	if length < c._SizeLower() {
		return false
	}

	if upper, bounded := c._SizeUpper(); bounded && length > upper {
		return false
	}

	return true
}

// _Root returns the constraint with its extension marker removed, which is how
// clauses 13.1, 16.6, 17.3, 20.4 and 23.7 encode a value that lies inside the
// root: as though the marker were not there.
//
// Revisions:
//   - 2026-09-22 06:43: initial creation
func (c *Constraint) _Root() *Constraint {
	if c == nil {
		return Unconstrained()
	}

	return &Constraint{
		lb: c.lb,
		ub: c.ub,
	}
}

// _Unbounded returns the length constraint that applies outside the extension
// root: a semi-constrained length with a lower bound of zero, per clauses 16.6,
// 17.3 and 20.4.
//
// Revisions:
//   - 2026-09-22 06:43: initial creation
func _Unbounded() *Constraint {
	return SemiConstrained(0)
}
