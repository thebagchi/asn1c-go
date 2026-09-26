package per

import (
	"fmt"
	"reflect"
	"strconv"
	"strings"
	"sync"
)

// Directives recognised inside a per:"..." struct tag. TAGS.md beside this file
// has a worked example of each.
const (
	TAG_KEY            = "per"
	TAG_OPTIONAL       = "opt"
	TAG_EXTENSIBLE     = "ext"
	TAG_OPEN           = "open"
	TAG_PREFIX_CHOICE  = "choice="
	TAG_PREFIX_ENUM    = "enum="
	TAG_PREFIX_LB      = "lb="
	TAG_PREFIX_UB      = "ub="
	TAG_PREFIX_DEFAULT = "def="
	TAG_PREFIX_STRING  = "str="
	TAG_PREFIX_ELEM    = "elem("
	TAG_ELEM_CLOSE     = ')'
	TAG_ELEM_OPEN      = '('
	TAG_SEPARATOR      = ","
)

// Caches keyed by reflect.Type. Parsing a tag and walking a struct both depend
// only on the type, so both are done once however many values are encoded.
var (
	TAG_CACHE = &TagCache{
		cache: make(map[reflect.Type]map[int]*Tag),
	}
	STRUCT_CACHE = &StructCache{
		cache: make(map[reflect.Type]*StructMeta),
	}
)

// Tag is a parsed per:"..." struct tag.
//
// The fields are unexported so a Tag can only come from ParseTag or
// GetFieldTag, which is what keeps a hand-built Tag from carrying a combination
// the parser would have rejected.
type Tag struct {
	def    *string
	lb     *int64
	ub     *int64
	choice *int
	enum   *uint64
	elem   *Tag
	kind   StringKind
	opt    bool
	ext    bool
	open   bool
}

// TagCache holds the parsed tag of every field of every struct type seen.
type TagCache struct {
	mtx   sync.RWMutex
	cache map[reflect.Type]map[int]*Tag
}

// StructCache holds the StructMeta of every struct type seen.
type StructCache struct {
	mtx   sync.RWMutex
	cache map[reflect.Type]*StructMeta
}

// StructMeta is what a struct type says about the ASN.1 type it represents,
// worked out once from its fields and their tags.
//
// Fields and Extensions hold field indices, split at the extension marker;
// Optionals is the subset of Fields that carry OPTIONAL or DEFAULT, in the order
// their presence bits appear in the preamble of X.691 clause 19.2.
type StructMeta struct {
	Fields     []int
	Extensions []int
	Optionals  []int
	Num        int
	Extensible bool
	Choice     bool
}

// ParseTag parses the body of a per:"..." struct tag.
//
// Revisions:
//   - 2026-03-02 22:36: initial creation
//   - 2026-09-22 06:43: rejects a directive it does not recognise. A typo such
//     as ubb=255 was skipped in silence, and the field then encoded
//     unconstrained, which is a valid encoding of the wrong type
func ParseTag(tag string) (*Tag, error) {
	result := new(Tag)
	if tag == "" {
		return result, nil
	}

	rest, err := result._TakeElem(tag)
	if err != nil {
		return nil, err
	}

	for part := range strings.SplitSeq(rest, TAG_SEPARATOR) {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}

		if err := result._Apply(part); err != nil {
			return nil, err
		}
	}

	return result, nil
}

// GetFieldTag returns the parsed tag of one field, parsing it on first use.
//
// The cache is keyed by type and field index rather than by the tag text, so two
// fields that happen to carry the same tag still resolve independently.
//
// Revisions:
//   - 2026-03-02 22:36: initial creation
func GetFieldTag(field reflect.StructField, parent reflect.Type, index int) (*Tag, error) {
	TAG_CACHE.mtx.RLock()

	if fields, ok := TAG_CACHE.cache[parent]; ok {
		if tag, ok := fields[index]; ok {
			TAG_CACHE.mtx.RUnlock()

			return tag, nil
		}
	}

	TAG_CACHE.mtx.RUnlock()

	TAG_CACHE.mtx.Lock()
	defer TAG_CACHE.mtx.Unlock()

	if fields, ok := TAG_CACHE.cache[parent]; ok {
		if tag, ok := fields[index]; ok {
			return tag, nil
		}
	}

	parsed, err := ParseTag(field.Tag.Get(TAG_KEY))
	if err != nil {
		return nil, fmt.Errorf("field %q of %v: %w", field.Name, parent, err)
	}

	if _, ok := TAG_CACHE.cache[parent]; !ok {
		TAG_CACHE.cache[parent] = make(map[int]*Tag)
	}

	TAG_CACHE.cache[parent][index] = parsed

	return parsed, nil
}

// GetStructMeta returns the metadata of a struct type, computing it on first use.
//
// Revisions:
//   - 2026-03-02 22:36: initial creation
func GetStructMeta(rt reflect.Type) (*StructMeta, error) {
	STRUCT_CACHE.mtx.RLock()

	if meta, ok := STRUCT_CACHE.cache[rt]; ok {
		STRUCT_CACHE.mtx.RUnlock()

		return meta, nil
	}

	STRUCT_CACHE.mtx.RUnlock()

	STRUCT_CACHE.mtx.Lock()
	defer STRUCT_CACHE.mtx.Unlock()

	if meta, ok := STRUCT_CACHE.cache[rt]; ok {
		return meta, nil
	}

	meta, err := MakeStructMeta(rt)
	if err != nil {
		return nil, err
	}

	STRUCT_CACHE.cache[rt] = meta

	return meta, nil
}

// MakeStructMeta works out what a struct type says about its ASN.1 type.
//
// Revisions:
//   - 2026-03-02 22:36: initial creation
//   - 2026-09-22 06:43: rejects an unexported field, a non-pointer extension
//     addition and a choice index that disagrees with its position. The first
//     reached reflect.Value.Interface and panicked; the second was present in
//     every encoding because a non-pointer is never absent; the third encoded
//     the position while the tag claimed otherwise
func MakeStructMeta(rt reflect.Type) (*StructMeta, error) {
	meta := &StructMeta{
		Num: rt.NumField(),
	}

	for i := range meta.Num {
		field := rt.Field(i)

		marker, err := _IsMarker(field, rt, i)
		if err != nil {
			return nil, err
		}

		if marker {
			if meta.Extensible {
				return nil, fmt.Errorf(
					"%v: field %d: second extension marker",
					rt, i,
				)
			}

			meta.Extensible = true

			continue
		}

		if !field.IsExported() {
			return nil, fmt.Errorf(
				"%v: field %q is unexported and cannot be encoded",
				rt, field.Name,
			)
		}

		if err := meta._Add(rt, field, i); err != nil {
			return nil, err
		}
	}

	return meta, nil
}

// FieldPresent reports whether a field holds a value. Only a pointer field can
// be absent, which is why an OPTIONAL field has to be one.
//
// Revisions:
//   - 2026-03-02 22:36: initial creation
func FieldPresent(v reflect.Value) bool {
	if v.Kind() == reflect.Pointer {
		return !v.IsNil()
	}

	return true
}

// FieldPresentForEncoding reports whether a field's presence bit is set in the
// preamble of X.691 clause 19.2.
//
// For a DEFAULT field that means the value differs from the default, because
// clause 19.5 has BASIC-PER omit a simple type holding its default value; for a
// plain OPTIONAL field it means the pointer is not nil.
//
// Revisions:
//   - 2026-07-05 18:20: initial creation
func FieldPresentForEncoding(v reflect.Value, tag *Tag) (bool, error) {
	if tag.def == nil {
		return FieldPresent(v), nil
	}

	equal, err := FieldEqualsDefault(v, *tag.def)
	if err != nil {
		return false, err
	}

	return !equal, nil
}

// FieldEqualsDefault reports whether v holds the DEFAULT value def describes. A
// nil pointer counts as equal, since an absent field decodes to the default.
//
// Revisions:
//   - 2026-07-05 18:20: initial creation
//   - 2026-09-22 06:43: compares against a parsed value of the field's own type
//     rather than repeating ApplyDefaultValue's switch with == in place of Set
func FieldEqualsDefault(v reflect.Value, def string) (bool, error) {
	if v.Kind() == reflect.Pointer {
		if v.IsNil() {
			return true, nil
		}

		v = v.Elem()
	}

	want := reflect.New(v.Type()).Elem()
	if err := _SetDefault(want, def); err != nil {
		return false, err
	}

	return v.Equal(want), nil
}

// ApplyDefaultValue assigns the DEFAULT value def describes to v, allocating v
// first if it is a nil pointer.
//
// Revisions:
//   - 2026-07-05 18:20: initial creation
func ApplyDefaultValue(v reflect.Value, def string) error {
	if v.Kind() == reflect.Pointer {
		if v.IsNil() {
			v.Set(reflect.New(v.Type().Elem()))
		}

		v = v.Elem()
	}

	return _SetDefault(v, def)
}

// Constraint returns the bounds and extension marker this tag describes.
//
// Revisions:
//   - 2026-09-22 06:43: initial creation
func (t *Tag) Constraint() *Constraint {
	if t == nil {
		return Unconstrained()
	}

	return &Constraint{
		lb:  t.lb,
		ub:  t.ub,
		ext: t.ext,
	}
}

// Elem returns the tag describing the elements of a SEQUENCE OF or SET OF, which
// is never nil so a caller can pass it on without checking.
//
// Revisions:
//   - 2026-09-22 06:43: initial creation
func (t *Tag) Elem() *Tag {
	if t == nil || t.elem == nil {
		return new(Tag)
	}

	return t.elem
}

// Optional reports whether the field is OPTIONAL or carries a DEFAULT, which is
// the same question the preamble of clause 19.2 answers.
//
// Revisions:
//   - 2026-09-22 06:43: initial creation
func (t *Tag) Optional() bool {
	return t != nil && (t.opt || t.def != nil)
}

// _WithoutOpen returns a copy of t with the open directive cleared, which is
// what stops an open type field from wrapping itself again inside its own
// encoding.
//
// Revisions:
//   - 2026-09-22 06:43: initial creation
func (t *Tag) _WithoutOpen() *Tag {
	inner := *t
	inner.open = false

	return &inner
}

// _TakeElem removes an elem(...) directive from tag and parses it into t,
// returning what is left.
//
// It runs before the tag is split on commas, because the directive it takes out
// contains commas of its own.
//
// Revisions:
//   - 2026-09-22 06:43: initial creation, split out of ParseTag
func (t *Tag) _TakeElem(tag string) (string, error) {
	start := strings.Index(tag, TAG_PREFIX_ELEM)
	if start < 0 {
		return tag, nil
	}

	var (
		open  = start + len(TAG_PREFIX_ELEM)
		depth = 1
		end   = -1
	)

	for i := open; i < len(tag) && end < 0; i++ {
		switch tag[i] {
		case TAG_ELEM_OPEN:
			depth++
		case TAG_ELEM_CLOSE:
			depth--
			if depth == 0 {
				end = i
			}
		}
	}

	if end < 0 {
		return "", fmt.Errorf("unmatched parenthesis in %q", TAG_PREFIX_ELEM)
	}

	elem, err := ParseTag(tag[open:end])
	if err != nil {
		return "", fmt.Errorf("%q: %w", TAG_PREFIX_ELEM, err)
	}

	t.elem = elem

	return tag[:start] + tag[end+1:], nil
}

// _Apply applies one comma-separated directive to t.
//
// Revisions:
//   - 2026-09-22 06:43: initial creation, split out of ParseTag
func (t *Tag) _Apply(part string) error {
	switch part {
	case TAG_OPTIONAL:
		t.opt = true

		return nil
	case TAG_EXTENSIBLE:
		t.ext = true

		return nil
	case TAG_OPEN:
		t.open = true

		return nil
	}

	if value, ok := strings.CutPrefix(part, TAG_PREFIX_DEFAULT); ok {
		trimmed := strings.Trim(value, `"`)
		t.def = &trimmed

		return nil
	}

	if value, ok := strings.CutPrefix(part, TAG_PREFIX_STRING); ok {
		kind, known := STRING_NAMES[value]
		if !known {
			return fmt.Errorf("unknown %q kind %q", TAG_PREFIX_STRING, value)
		}

		t.kind = kind

		return nil
	}

	return t._ApplyNumeric(part)
}

// _ApplyNumeric applies one directive whose argument is a number.
//
// Revisions:
//   - 2026-09-22 06:43: initial creation, split out of ParseTag
func (t *Tag) _ApplyNumeric(part string) error {
	if value, ok := strings.CutPrefix(part, TAG_PREFIX_CHOICE); ok {
		return _ParseInto(part, value, func(n int64) {
			index := int(n)
			t.choice = &index
		})
	}

	if value, ok := strings.CutPrefix(part, TAG_PREFIX_ENUM); ok {
		return _ParseInto(part, value, func(n int64) {
			count := uint64(n)
			t.enum = &count
		})
	}

	if value, ok := strings.CutPrefix(part, TAG_PREFIX_LB); ok {
		return _ParseInto(part, value, func(n int64) { t.lb = &n })
	}

	if value, ok := strings.CutPrefix(part, TAG_PREFIX_UB); ok {
		return _ParseInto(part, value, func(n int64) { t.ub = &n })
	}

	return fmt.Errorf("unknown %q directive %q", TAG_KEY, part)
}

// _Add records one non-marker field in the metadata.
//
// Revisions:
//   - 2026-09-22 06:43: initial creation, split out of MakeStructMeta
func (m *StructMeta) _Add(rt reflect.Type, field reflect.StructField, index int) error {
	tag, err := GetFieldTag(field, rt, index)
	if err != nil {
		return fmt.Errorf("%v: field %q: %w", rt, field.Name, err)
	}

	if m.Extensible {
		if err := _CheckPointer(rt, field, tag, true); err != nil {
			return err
		}

		if err := _CheckChoice(rt, field, tag, len(m.Extensions)); err != nil {
			return err
		}

		m.Extensions = append(m.Extensions, index)

		return nil
	}

	if err := _CheckChoice(rt, field, tag, len(m.Fields)); err != nil {
		return err
	}

	if err := _CheckPointer(rt, field, tag, false); err != nil {
		return err
	}

	if tag.choice != nil {
		m.Choice = true
	}

	m.Fields = append(m.Fields, index)
	if tag.Optional() {
		m.Optionals = append(m.Optionals, index)
	}

	return nil
}

// _CheckPointer reports a field that has to be able to be absent but is not a
// pointer, which is the only way a Go value can be.
//
// An extension addition, a CHOICE alternative and an OPTIONAL field are all such
// fields: a non-pointer among them reads as present in every encoding, so the
// extension bit or the presence bit would never be zero.
//
// Revisions:
//   - 2026-09-22 06:43: initial creation, split out of StructMeta._Add
func _CheckPointer(rt reflect.Type, field reflect.StructField, tag *Tag, addition bool) error {
	if field.Type.Kind() == reflect.Pointer {
		return nil
	}

	role := ""

	switch {
	case addition:
		role = "extension addition"
	case tag.choice != nil:
		role = "choice alternative"
	case tag.opt:
		role = "optional field"
	default:
		return nil
	}

	return fmt.Errorf(
		"%v: %s %q must be a pointer, so it can be absent",
		rt, role, field.Name,
	)
}

// _IsMarker reports whether a field is the `_ struct{}` extension marker.
//
// Revisions:
//   - 2026-09-22 06:43: initial creation, split out of MakeStructMeta
func _IsMarker(field reflect.StructField, rt reflect.Type, index int) (bool, error) {
	if field.Name != "_" || field.Type != TYPE_MARKER {
		return false, nil
	}

	tag, err := GetFieldTag(field, rt, index)
	if err != nil {
		return false, fmt.Errorf("%v: field %d: %w", rt, index, err)
	}

	return tag.ext, nil
}

// _CheckChoice reports a choice index that disagrees with the alternative's
// position.
//
// X.691 clause 23.2 numbers alternatives by their canonical order, and numbers
// the extension additions from zero again, so the position is the index. The
// directive is therefore documentation, and this is what keeps it honest.
//
// Revisions:
//   - 2026-09-22 06:43: initial creation
func _CheckChoice(rt reflect.Type, field reflect.StructField, tag *Tag, pos int) error {
	if tag.choice == nil || *tag.choice == pos {
		return nil
	}

	return fmt.Errorf(
		"%v: field %q has %s%d but is alternative %d of its list",
		rt, field.Name, TAG_PREFIX_CHOICE, *tag.choice, pos,
	)
}

// _ParseInto parses a directive's numeric argument and hands it to set.
//
// Revisions:
//   - 2026-09-22 06:43: initial creation
func _ParseInto(part, value string, set func(int64)) error {
	if value == "" {
		return fmt.Errorf("empty value in %q", part)
	}

	number, err := strconv.ParseInt(value, DECIMAL_BASE, 64)
	if err != nil {
		return fmt.Errorf("invalid value in %q: %w", part, err)
	}

	set(number)

	return nil
}

// _SetDefault parses def according to v's kind and assigns it.
//
// Revisions:
//   - 2026-09-22 06:43: initial creation, shared by ApplyDefaultValue and
//     FieldEqualsDefault, which had a copy of this switch each
func _SetDefault(v reflect.Value, def string) error {
	switch v.Kind() {
	case reflect.Bool:
		parsed, err := strconv.ParseBool(def)
		if err != nil {
			return fmt.Errorf("default %q: %w", def, err)
		}

		v.SetBool(parsed)
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		parsed, err := strconv.ParseInt(def, DECIMAL_BASE, 64)
		if err != nil {
			return fmt.Errorf("default %q: %w", def, err)
		}

		v.SetInt(parsed)
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
		parsed, err := strconv.ParseUint(def, DECIMAL_BASE, 64)
		if err != nil {
			return fmt.Errorf("default %q: %w", def, err)
		}

		v.SetUint(parsed)
	case reflect.Float32, reflect.Float64:
		parsed, err := strconv.ParseFloat(def, 64)
		if err != nil {
			return fmt.Errorf("default %q: %w", def, err)
		}

		v.SetFloat(parsed)
	case reflect.String:
		v.SetString(def)
	default:
		return fmt.Errorf("default %q: unsupported kind %s", def, v.Kind())
	}

	return nil
}
