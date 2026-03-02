package per

import (
	"fmt"
	"reflect"
	"strconv"
	"strings"
	"sync"
)

// Example usage:
//
//		------------------ ENUMERATED ------------------
//		type StatusType uint64
//
//		const (
//			StatusIdle       StatusType = iota // 0: System is idle
//			StatusConnecting                   // 1: Establishing connection
//			StatusActive                       // 2: System is active
//			StatusError                        // 3: Error state
//			// Future extension values would start at 4 or higher
//		)
//
//		------------------ CHOICE ------------------
//		type BandwidthConfig struct {
//			Value int64 `per:"lb=1,ub=10000"` // Bandwidth value in Mbps (1-10000)
//		}
//		type ActionChoice struct {
//			// Root alternatives (indices 0–2)
//			Start  *bool            `per:"choice=0"`   // Start operation
//			Stop   *bool            `per:"choice=1"`   // Stop operation
//			Config *BandwidthConfig `per:"choice=2"`   // Configure bandwidth
//			_      struct{}         `per:"ext"`        // Extension marker
//			Pause  *bool            `per:"choice=3"`   // Pause operation (extension)
//			Resume *bool            `per:"choice=4"`   // Resume operation (extension)
//			Reboot *bool            `per:"choice=5"`   // Reboot system (extension)
//		}
//
//
//		------------------ SEQUENCE OF (List) ------------------
//		type Channel struct {
//			ID    int64 `per:"lb=1,ub=1000"` // Channel identifier (1-1000)
//			Power int64 `per:"lb=0,ub=100"`  // Power level in dBm (0-100)
//		}
//		type ChannelList struct {
//			FixedChannels      [8]Channel `per:"lb=8,ub=8"`            // Exactly 8 channels required
//			VariableChannels   []Channel  `per:"lb=0,ub=16"`           // 0-16 channels allowed
//			ExtensibleChannels []Channel  `per:"lb=1,ub=5,ext"`        // 1-5 in root, extensible
//		}
//
//		------------------ FULL CONSOLIDATED EXAMPLE ------------------
//		type FullMessage struct {
//			MessageID     int64            `per:"lb=1,ub=100000"`       // Unique message identifier (1-100000)
//			Priority      *int64           `per:"lb=0,ub=10"`           // Message priority level (0-10, optional)
//			Flags         asn1.BitString   `per:"lb=32,ub=32"`          // Fixed 32-bit flag set
//			Mask          asn1.BitString   `per:"lb=0,ub=64"`           // Variable mask up to 64 bits
//			Payload       []byte           `per:"lb=0,ub=1024"`         // Binary payload data (0-1024 bytes)
//			Status        StatusType       `per:"enum=4,ext"`           // Current system status (4 root values + extensible)
//			Action        ActionChoice     `per:"ext"`                  // Action to perform (extensible choice)
//			Channels      []Channel        `per:"lb=1,ub=8,ext"`        // List of channels (1-8 in root, extensible)
//			_             struct{}         `per:"ext"`                  // Extension marker for the SEQUENCE
//			FutureVersion *int64           `per:""`                     // Future version field (extension)
//			Experimental  *BandwidthConfig `per:""`                     // Experimental bandwidth config (extension)
//		}

const (
	TAG_KEY            = "per"
	TAG_OPTIONAL       = "opt"
	TAG_EXTENSIBLE     = "ext"
	TAG_PREFIX_CHOICE  = "choice="
	TAG_PREFIX_ENUM    = "enum="
	TAG_PREFIX_LB      = "lb="
	TAG_PREFIX_UB      = "ub="
	TAG_PREFIX_DEFAULT = "def="
)

type Tag struct {
	Opt    bool    // field is OPTIONAL
	Def    *string // default value (as string); empty string is distinct from nil
	Ext    bool    // type has ... (extensible)
	LB     *int64  // lower bound
	UB     *int64  // upper bound
	Choice *int    // CHOICE alternative index
	Enum   *uint64 // ENUMERATED root value count
}

func parseTag(tag string) (*Tag, error) {
	result := &Tag{}

	if tag == "" {
		return result, nil
	}

	for part := range strings.SplitSeq(tag, ",") {
		part = strings.TrimSpace(part)

		switch {
		case part == TAG_OPTIONAL:
			result.Opt = true

		case part == TAG_EXTENSIBLE:
			result.Ext = true

		case strings.HasPrefix(part, TAG_PREFIX_CHOICE):
			s := strings.TrimPrefix(part, TAG_PREFIX_CHOICE)
			if s == "" {
				return nil, fmt.Errorf("empty value for %q tag", TAG_PREFIX_CHOICE)
			}
			v, err := strconv.Atoi(s)
			if err != nil {
				return nil, fmt.Errorf("invalid %q value %q: %w", TAG_PREFIX_CHOICE, s, err)
			}
			result.Choice = &v

		case strings.HasPrefix(part, TAG_PREFIX_ENUM):
			s := strings.TrimPrefix(part, TAG_PREFIX_ENUM)
			if s == "" {
				return nil, fmt.Errorf("empty value for %q tag", TAG_PREFIX_ENUM)
			}
			v, err := strconv.ParseUint(s, 10, 64)
			if err != nil {
				return nil, fmt.Errorf("invalid %q value %q: %w", TAG_PREFIX_ENUM, s, err)
			}
			result.Enum = &v

		case strings.HasPrefix(part, TAG_PREFIX_LB):
			s := strings.TrimPrefix(part, TAG_PREFIX_LB)
			if s == "" {
				return nil, fmt.Errorf("empty value for %q tag", TAG_PREFIX_LB)
			}
			v, err := strconv.ParseInt(s, 10, 64)
			if err != nil {
				return nil, fmt.Errorf("invalid %q value %q: %w", TAG_PREFIX_LB, s, err)
			}
			result.LB = &v

		case strings.HasPrefix(part, TAG_PREFIX_UB):
			s := strings.TrimPrefix(part, TAG_PREFIX_UB)
			if s == "" {
				return nil, fmt.Errorf("empty value for %q tag", TAG_PREFIX_UB)
			}
			v, err := strconv.ParseInt(s, 10, 64)
			if err != nil {
				return nil, fmt.Errorf("invalid %q value %q: %w", TAG_PREFIX_UB, s, err)
			}
			result.UB = &v

		case strings.HasPrefix(part, TAG_PREFIX_DEFAULT):
			val := strings.Trim(strings.TrimPrefix(part, TAG_PREFIX_DEFAULT), `"`)
			result.Def = &val
		}
	}

	return result, nil
}

// TagCache provides thread-safe caching of parsed struct field tags
// Maps from (struct type, field index) to parsed Tag
type TagCache struct {
	mtx   sync.RWMutex
	cache map[reflect.Type]map[int]*Tag
}

var tagCache = &TagCache{
	cache: make(map[reflect.Type]map[int]*Tag),
}

// StructMeta holds pre-computed structural metadata for a struct type.
// This is derived entirely from the reflect.Type and PER struct tags,
// so it can be computed once and cached per type.
type StructMeta struct {
	Num        int   // total number of struct fields
	Extensible bool  // true if struct has a `_ struct{} per:"ext"` extension marker
	Choice     bool  // true if struct represents a CHOICE (fields have `choice=N` tags)
	Fields     []int // field indices in the root component (before the extension marker)
	Extensions []int // field indices of extension additions (after the extension marker)
	Optionals  []int // subset of Fields that are OPTIONAL/DEFAULT/pointer
}

// StructCache provides thread-safe caching of StructMeta per reflect.Type
type StructCache struct {
	mtx   sync.RWMutex
	cache map[reflect.Type]*StructMeta
}

var structCache = &StructCache{
	cache: make(map[reflect.Type]*StructMeta),
}

// GetStructMeta returns the cached StructMeta for a struct type, computing it on first access.
func GetStructMeta(rt reflect.Type) (*StructMeta, error) {
	// Fast path: read lock
	structCache.mtx.RLock()
	if meta, exists := structCache.cache[rt]; exists {
		structCache.mtx.RUnlock()
		return meta, nil
	}
	structCache.mtx.RUnlock()

	// Slow path: compute and cache under write lock
	structCache.mtx.Lock()
	defer structCache.mtx.Unlock()

	// Double-check after acquiring write lock
	if meta, exists := structCache.cache[rt]; exists {
		return meta, nil
	}

	meta, err := MakeStructMeta(rt)
	if err != nil {
		return nil, err
	}
	structCache.cache[rt] = meta
	return meta, nil
}

// MakeStructMeta computes the StructMeta for a struct type.
func MakeStructMeta(rt reflect.Type) (*StructMeta, error) {
	num := rt.NumField()

	extensible := false
	choice := false
	var fields, extensions, optionals []int

	for i := range num {
		field := rt.Field(i)
		// Extension marker field: `_ struct{} per:"ext"` — marks the boundary
		if field.Name == "_" && field.Type == EmptyType {
			tag, err := GetFieldTag(field, rt, i)
			if err != nil {
				return nil, fmt.Errorf("StructMeta: field %d: %w", i, err)
			}
			if tag.Ext {
				extensible = true
			}
			continue
		}

		if !extensible {
			fields = append(fields, i)

			tag, err := GetFieldTag(field, rt, i)
			if err != nil {
				return nil, fmt.Errorf("StructMeta: field %q: %w", field.Name, err)
			}
			if tag.Choice != nil {
				choice = true
			}
			if tag.Opt && field.Type.Kind() != reflect.Pointer {
				return nil, fmt.Errorf("StructMeta: field %q is tagged optional but is not a pointer type", field.Name)
			}
			if tag.Opt || tag.Def != nil {
				optionals = append(optionals, i)
			}
		} else {
			extensions = append(extensions, i)
		}
	}

	return &StructMeta{
		Num:        num,
		Extensible: extensible,
		Choice:     choice,
		Fields:     fields,
		Extensions: extensions,
		Optionals:  optionals,
	}, nil
}

// GetFieldTag returns the parsed tag for a struct field, using a cache to avoid re-parsing.
// Lookup key is (struct type, field index) to ensure unique identification.
func GetFieldTag(field reflect.StructField, parent reflect.Type, index int) (*Tag, error) {
	// Fast path: read lock check
	tagCache.mtx.RLock()
	if typeCache, exists := tagCache.cache[parent]; exists {
		if tag, exists := typeCache[index]; exists {
			tagCache.mtx.RUnlock()
			return tag, nil
		}
	}
	tagCache.mtx.RUnlock()

	// Slow path: acquire write lock and double-check before parsing
	tagCache.mtx.Lock()
	defer tagCache.mtx.Unlock()

	// Double-check: another goroutine may have populated while we waited
	if typeCache, exists := tagCache.cache[parent]; exists {
		if tag, exists := typeCache[index]; exists {
			return tag, nil
		}
	}

	parsed, err := parseTag(field.Tag.Get(TAG_KEY))
	if err != nil {
		return nil, fmt.Errorf("field %q of %v: %w", field.Name, parent, err)
	}

	if _, exists := tagCache.cache[parent]; !exists {
		tagCache.cache[parent] = make(map[int]*Tag)
	}
	tagCache.cache[parent][index] = parsed

	return parsed, nil
}

// FieldPresent returns true if the struct field value is "present".
// A pointer field is present if non-nil. All non-pointer fields are always present.
func FieldPresent(v reflect.Value) bool {
	if v.Kind() == reflect.Pointer {
		return !v.IsNil()
	}
	return true
}
