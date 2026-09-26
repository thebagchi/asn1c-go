package compiler

import "regexp"

// The three lexical rules that are checked rather than matched. The lexer
// finds tokens with the streaming expressions in lexer.go; these say what
// a token that was found must look like, which is a different question and
// one the specifications ask in only three places.
//
// X.680 clause 12 and X.681 clause 7 define two dozen more lexical items,
// and every one of them is either a shape the streaming set already
// matches or a name for a shape another item shares - a "valuereference"
// is an "identifier", a "modulereference" is a "typereference", and X.680
// 12.4 and 12.5 say so themselves. Transcribing those here as a second set
// of expressions left twenty-nine that nothing read and that said, wrongly,
// that the lexer had a rule of its own for each.
var (
	// RE_TYPE_REFERENCE tells a typereference from an identifier, which
	// is the one distinction the lexer makes by shape (see _LexName).
	RE_TYPE_REFERENCE = regexp.MustCompile(`^[A-Z][A-Za-z0-9]*(-[A-Za-z0-9]+)*$`)

	// RE_ENCODING_REFERENCE is X.680 12.25: an encodingreference is a
	// typereference with no lower-case letter in it. The lexer cannot tell
	// the two apart and does not try; whoever resolves names checks this.
	// X.681 7.1's objectclassreference is the same rule.
	RE_ENCODING_REFERENCE = regexp.MustCompile(`^[A-Z][A-Z0-9]*(-[A-Z0-9]+)*$`)

	// RE_WORD is X.681 7.9: a word, which a class may use in the syntax it
	// declares, is a typereference with neither lower-case letters nor
	// digits. The grammar's Literal rule takes any typereference, so this
	// is the check that says which of them a class may actually use.
	RE_WORD = regexp.MustCompile(`^[A-Z]+(-[A-Z]+)*$`)
)

// The ASN.1 reserved words of X.680 clause 12.38, as the text each is spelled
// with. tokens.go maps every one of them to the token goyacc assigns it.
const (
	ABSENT                 = "ABSENT"
	ABSTRACT_SYNTAX        = "ABSTRACT-SYNTAX"
	ALL                    = "ALL"
	APPLICATION            = "APPLICATION"
	AUTOMATIC              = "AUTOMATIC"
	BEGIN                  = "BEGIN"
	BIT                    = "BIT"
	BMP_STRING             = "BMPString"
	BOOLEAN                = "BOOLEAN"
	BY                     = "BY"
	CHARACTER              = "CHARACTER"
	CHOICE                 = "CHOICE"
	CLASS                  = "CLASS"
	COMPONENT              = "COMPONENT"
	COMPONENTS             = "COMPONENTS"
	CONSTRAINED            = "CONSTRAINED"
	CONTAINING             = "CONTAINING"
	DATE                   = "DATE"
	DATE_TIME              = "DATE-TIME"
	DEFAULT                = "DEFAULT"
	DEFINITIONS            = "DEFINITIONS"
	DURATION               = "DURATION"
	EMBEDDED               = "EMBEDDED"
	ENCODED                = "ENCODED"
	ENCODING_CONTROL       = "ENCODING-CONTROL"
	END                    = "END"
	ENUMERATED             = "ENUMERATED"
	EXCEPT                 = "EXCEPT"
	EXPLICIT               = "EXPLICIT"
	EXPORTS                = "EXPORTS"
	EXTENSIBILITY          = "EXTENSIBILITY"
	EXTERNAL               = "EXTERNAL"
	FALSE                  = "FALSE"
	FROM                   = "FROM"
	GENERALIZED_TIME       = "GeneralizedTime"
	GENERAL_STRING         = "GeneralString"
	GRAPHIC_STRING         = "GraphicString"
	IA5_STRING             = "IA5String"
	IDENTIFIER             = "IDENTIFIER"
	IMPLICIT               = "IMPLICIT"
	IMPLIED                = "IMPLIED"
	IMPORTS                = "IMPORTS"
	INCLUDES               = "INCLUDES"
	INSTANCE               = "INSTANCE"
	INSTRUCTIONS           = "INSTRUCTIONS"
	INTEGER                = "INTEGER"
	INTERSECTION           = "INTERSECTION"
	ISO646_STRING          = "ISO646String"
	MAX                    = "MAX"
	MIN                    = "MIN"
	MINUS_INFINITY         = "MINUS-INFINITY"
	NOT_A_NUMBER           = "NOT-A-NUMBER"
	NULL                   = "NULL"
	NUMERIC_STRING         = "NumericString"
	OBJECT                 = "OBJECT"
	OBJECT_DESCRIPTOR      = "ObjectDescriptor"
	OCTET                  = "OCTET"
	OF                     = "OF"
	OID_IRI                = "OID-IRI"
	OPTIONAL               = "OPTIONAL"
	PATTERN                = "PATTERN"
	PDV                    = "PDV"
	PLUS_INFINITY          = "PLUS-INFINITY"
	PRESENT                = "PRESENT"
	PRINTABLE_STRING       = "PrintableString"
	PRIVATE                = "PRIVATE"
	REAL                   = "REAL"
	RELATIVE_OID           = "RELATIVE-OID"
	RELATIVE_OID_IRI       = "RELATIVE-OID-IRI"
	SEQUENCE               = "SEQUENCE"
	SET                    = "SET"
	SETTINGS               = "SETTINGS"
	SIZE                   = "SIZE"
	STRING                 = "STRING"
	SYNTAX                 = "SYNTAX"
	T61_STRING             = "T61String"
	TAGS                   = "TAGS"
	TELETEX_STRING         = "TeletexString"
	TIME                   = "TIME"
	TIME_OF_DAY            = "TIME-OF-DAY"
	TRUE                   = "TRUE"
	TYPE_IDENTIFIER        = "TYPE-IDENTIFIER"
	UNION                  = "UNION"
	UNIQUE                 = "UNIQUE"
	UNIVERSAL              = "UNIVERSAL"
	UNIVERSAL_STRING       = "UniversalString"
	UTC_TIME               = "UTCTime"
	UTF8_STRING            = "UTF8String"
	VIDEOTEX_STRING        = "VideotexString"
	VISIBLE_STRING         = "VisibleString"
	WITH                   = "WITH"
	LEFT_CURLY_BRACKET     = "{"
	RIGHT_CURLY_BRACKET    = "}"
	LESS_THAN_SIGN         = "<"
	GREATER_THAN_SIGN      = ">"
	COMMA                  = ","
	FULL_STOP              = "."
	SOLIDUS                = "/"
	LEFT_PARENTHESIS       = "("
	RIGHT_PARENTHESIS      = ")"
	LEFT_SQUARE_BRACKET    = "["
	RIGHT_SQUARE_BRACKET   = "]"
	HYPHEN_MINUS           = "-"
	COLON                  = ":"
	EQUALS_SIGN            = "="
	QUOTATION_MARK         = "\""
	APOSTROPHE             = "'"
	SEMICOLON              = ";"
	COMMERCIAL_AT          = "@"
	VERTICAL_LINE          = "|"
	EXCLAMATION_MARK       = "!"
	CIRCUMFLEX_ACCENT      = "^"
	ASSIGNMENT             = "::="
	RANGE_SEPARATOR        = ".."
	ELLIPSIS               = "..."
	LEFT_VERSION_BRACKETS  = "[["
	RIGHT_VERSION_BRACKETS = "]]"
	BLOCK_COMMENT_OPEN     = "/*"
	BLOCK_COMMENT_CLOSE    = "*/"
	XML_END_TAG_START      = "</"
	XML_SINGLE_TAG_END     = "/>"
	XML_BOOLEAN_TRUE       = "true"
	XML_BOOLEAN_FALSE      = "false"
	XML_REAL_NOT_A_NUMBER  = "NaN"
	XML_REAL_INFINITY      = "INF"
)

// The two words a SelectionOption may use after WITH (X.680 13.1). They sit
// apart from the block above because X.680 quotes them in the syntax rather
// than listing them in clause 12.38: they are not reserved words, a module
// may still use either as a typereference, and the lexer therefore returns
// them as one. Only the grammar's SelectionOption rule tells them apart.
const (
	SUCCESSORS  = "SUCCESSORS"
	DESCENDANTS = "DESCENDANTS"
)

// The built-in types X.680 spells with two reserved words, as the one name
// each carries in the AST. They are written out rather than joined from the
// two constants above at each use, so the space between the words is spelled
// once and a reader sees the name a module would write.
const (
	BIT_STRING        = "BIT STRING"
	OCTET_STRING      = "OCTET STRING"
	OBJECT_IDENTIFIER = "OBJECT IDENTIFIER"
	CHARACTER_STRING  = "CHARACTER STRING"
	EMBEDDED_PDV      = "EMBEDDED PDV"
	SEQUENCE_OF       = "SEQUENCE OF"
	SET_OF            = "SET OF"
	INSTANCE_OF       = "INSTANCE OF"
)
