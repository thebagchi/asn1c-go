package compiler

// The TOK_* constants this file maps to are declared by %token in grammar.y
// and generated into grammar.go, so goyacc alone numbers them: a token the
// lexer returns is only meaningful to the parser if the parser was built
// knowing it. Adding a lexeme here means adding its %token there.

// KEYWORD_TOKENS maps every ASN.1 reserved word to its token. Keys reuse the
// string constants declared in constants.go.
var (
	KEYWORD_TOKENS = map[string]int{
		ABSENT:            TOK_ABSENT,
		ABSTRACT_SYNTAX:   TOK_ABSTRACT_SYNTAX,
		ALL:               TOK_ALL,
		APPLICATION:       TOK_APPLICATION,
		AUTOMATIC:         TOK_AUTOMATIC,
		BEGIN:             TOK_BEGIN,
		BIT:               TOK_BIT,
		BMP_STRING:        TOK_BMP_STRING,
		BOOLEAN:           TOK_BOOLEAN,
		BY:                TOK_BY,
		CHARACTER:         TOK_CHARACTER,
		CHOICE:            TOK_CHOICE,
		CLASS:             TOK_CLASS,
		COMPONENT:         TOK_COMPONENT,
		COMPONENTS:        TOK_COMPONENTS,
		CONSTRAINED:       TOK_CONSTRAINED,
		CONTAINING:        TOK_CONTAINING,
		DATE:              TOK_DATE,
		DATE_TIME:         TOK_DATE_TIME,
		DEFAULT:           TOK_DEFAULT,
		DEFINITIONS:       TOK_DEFINITIONS,
		DURATION:          TOK_DURATION,
		EMBEDDED:          TOK_EMBEDDED,
		ENCODED:           TOK_ENCODED,
		ENCODING_CONTROL:  TOK_ENCODING_CONTROL,
		END:               TOK_END,
		ENUMERATED:        TOK_ENUMERATED,
		EXCEPT:            TOK_EXCEPT,
		EXPLICIT:          TOK_EXPLICIT,
		EXPORTS:           TOK_EXPORTS,
		EXTENSIBILITY:     TOK_EXTENSIBILITY,
		EXTERNAL:          TOK_EXTERNAL,
		FALSE:             TOK_FALSE,
		FROM:              TOK_FROM,
		GENERALIZED_TIME:  TOK_GENERALIZED_TIME,
		GENERAL_STRING:    TOK_GENERAL_STRING,
		GRAPHIC_STRING:    TOK_GRAPHIC_STRING,
		IA5_STRING:        TOK_IA5_STRING,
		IDENTIFIER:        TOK_IDENTIFIER,
		IMPLICIT:          TOK_IMPLICIT,
		IMPLIED:           TOK_IMPLIED,
		IMPORTS:           TOK_IMPORTS,
		INCLUDES:          TOK_INCLUDES,
		INSTANCE:          TOK_INSTANCE,
		INSTRUCTIONS:      TOK_INSTRUCTIONS,
		INTEGER:           TOK_INTEGER,
		INTERSECTION:      TOK_INTERSECTION,
		ISO646_STRING:     TOK_ISO646_STRING,
		MAX:               TOK_MAX,
		MIN:               TOK_MIN,
		MINUS_INFINITY:    TOK_MINUS_INFINITY,
		NOT_A_NUMBER:      TOK_NOT_A_NUMBER,
		NULL:              TOK_NULL,
		NUMERIC_STRING:    TOK_NUMERIC_STRING,
		OBJECT:            TOK_OBJECT,
		OBJECT_DESCRIPTOR: TOK_OBJECT_DESCRIPTOR,
		OCTET:             TOK_OCTET,
		OF:                TOK_OF,
		OID_IRI:           TOK_OID_IRI,
		OPTIONAL:          TOK_OPTIONAL,
		PATTERN:           TOK_PATTERN,
		PDV:               TOK_PDV,
		PLUS_INFINITY:     TOK_PLUS_INFINITY,
		PRESENT:           TOK_PRESENT,
		PRINTABLE_STRING:  TOK_PRINTABLE_STRING,
		PRIVATE:           TOK_PRIVATE,
		REAL:              TOK_REAL,
		RELATIVE_OID:      TOK_RELATIVE_OID,
		RELATIVE_OID_IRI:  TOK_RELATIVE_OID_IRI,
		SEQUENCE:          TOK_SEQUENCE,
		SET:               TOK_SET,
		SETTINGS:          TOK_SETTINGS,
		SIZE:              TOK_SIZE,
		STRING:            TOK_STRING,
		SYNTAX:            TOK_SYNTAX,
		T61_STRING:        TOK_T61_STRING,
		TAGS:              TOK_TAGS,
		TELETEX_STRING:    TOK_TELETEX_STRING,
		TIME:              TOK_TIME,
		TIME_OF_DAY:       TOK_TIME_OF_DAY,
		TRUE:              TOK_TRUE,
		TYPE_IDENTIFIER:   TOK_TYPE_IDENTIFIER,
		UNION:             TOK_UNION,
		UNIQUE:            TOK_UNIQUE,
		UNIVERSAL:         TOK_UNIVERSAL,
		UNIVERSAL_STRING:  TOK_UNIVERSAL_STRING,
		UTC_TIME:          TOK_UTC_TIME,
		UTF8_STRING:       TOK_UTF8_STRING,
		VIDEOTEX_STRING:   TOK_VIDEOTEX_STRING,
		VISIBLE_STRING:    TOK_VISIBLE_STRING,
		WITH:              TOK_WITH,
	}
)

// Punctuation pairs a multi-character punctuation lexeme with its token.
type Punctuation struct {
	text  string
	token int
}

// PUNCTUATION_TOKENS lists the punctuation lexical items, ordered from
// longest to shortest so that, e.g., "..." is matched before ".." before
// ".", and "::=" before ":". The single-character items are last for that
// reason, and they are here rather than left to the rune each one is,
// because a rule that says TOK_COMMA reads better than one that says ','
// and cannot be confused with a character in a lexeme.
var (
	PUNCTUATION_TOKENS = []Punctuation{
		{ASSIGNMENT, TOK_ASSIGNMENT},
		{ELLIPSIS, TOK_ELLIPSIS},
		{LEFT_VERSION_BRACKETS, TOK_LEFT_VERSION_BRACKETS},
		{RIGHT_VERSION_BRACKETS, TOK_RIGHT_VERSION_BRACKETS},
		{XML_END_TAG_START, TOK_XML_END_TAG_START},
		{XML_SINGLE_TAG_END, TOK_XML_SINGLE_TAG_END},
		{RANGE_SEPARATOR, TOK_RANGE_SEPARATOR},
		{EXCLAMATION_MARK, TOK_EXCLAMATION_MARK},
		{LEFT_PARENTHESIS, TOK_LEFT_PARENTHESIS},
		{RIGHT_PARENTHESIS, TOK_RIGHT_PARENTHESIS},
		{COMMA, TOK_COMMA},
		{HYPHEN_MINUS, TOK_HYPHEN_MINUS},
		{FULL_STOP, TOK_FULL_STOP},
		{COLON, TOK_COLON},
		{SEMICOLON, TOK_SEMICOLON},
		{LESS_THAN_SIGN, TOK_LESS_THAN_SIGN},
		{COMMERCIAL_AT, TOK_COMMERCIAL_AT},
		{LEFT_SQUARE_BRACKET, TOK_LEFT_SQUARE_BRACKET},
		{RIGHT_SQUARE_BRACKET, TOK_RIGHT_SQUARE_BRACKET},
		{CIRCUMFLEX_ACCENT, TOK_CIRCUMFLEX_ACCENT},
		{LEFT_CURLY_BRACKET, TOK_LEFT_CURLY_BRACKET},
		{VERTICAL_LINE, TOK_VERTICAL_LINE},
		{RIGHT_CURLY_BRACKET, TOK_RIGHT_CURLY_BRACKET},
	}
)
