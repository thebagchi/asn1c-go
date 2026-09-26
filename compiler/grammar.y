// This is a goyacc grammar for ASN.1. It recognizes the whole of X.680's
// ModuleDefinition header, the exports and imports its body opens with,
// and the type, value and value set assignments that follow, over every
// built-in type X.680 defines, with constraints and parameterization:
//
//	<modulereference> [ { <arc>... } [ <iri> ] ]
//	DEFINITIONS
//	[ <encodingreference> INSTRUCTIONS ]
//	[ EXPLICIT | IMPLICIT | AUTOMATIC TAGS ]
//	[ EXTENSIBILITY IMPLIED ]
//	::= BEGIN
//	  [ EXPORTS ... ; ]
//	  [ IMPORTS ... ; ]
//	  <TypeReference> ::= <Type>           ...
//	  <valuereference> <Type> ::= <Value>  ...
//	END
//
// e.g. `Sample DEFINITIONS AUTOMATIC TAGS ::= BEGIN Person ::= SEQUENCE {
// name IA5String, age INTEGER (0..150) OPTIONAL, ... } END`.
//
// Every production of specs/asn1.ebnf is accounted for, and what accounts
// for each one is compiler/testdata/coverage.tsv, which coverage_test.go
// checks against this file. Most of X.680 is a rule here; X.683's
// parameterization is in; X.681's class definitions with their WITH SYNTAX
// word lists are in, and so are the places a class or an object reaches a
// type; X.682's CONSTRAINED BY and its two table constraints are in, the
// latter through the pattern section at the foot of this file.
//
// Three things are not rules, and cannot be. An object written in its
// class's own syntax, and an XML typed value, are chosen between by the
// class or the type rather than by any token, so the lexer keeps each whole
// and the pass that has the class or the type reads it. An encoding
// instruction has no production in X.680 at all - each encoding-rules
// standard defines its own - so the brackets of an encoding prefix are kept
// whole too. lib/review.md has the evidence for all three.
//
// The grammar is kept free of shift/reduce and reduce/reduce conflicts
// rather than resolved by precedence or %expect, so "0 shift/reduce, 0
// reduce/reduce" in y.output is the gate on every change to this file.
//
// A custom prefix ("asn1") is used so the generated helper identifiers
// (asn1SymType, asn1Parse, asn1Lexer, ...) don't collide with anything in
// lexer.go. Every token the Lexer can return is declared below, so goyacc
// alone assigns their numbers: the parser's token translation table is
// built from these declarations, and a number the lexer invents outside
// them reaches the parser as $unk no matter what it was named. tokens.go
// keeps only the maps from lexeme to token (see KEYWORD_TOKENS there).
%{
package compiler

import (
	"github.com/thebagchi/asn1c-go/ast"
)


// The lexeme types a token carries. STR/BOOL, rather than STRING/BOOLEAN
// which would otherwise be the natural names, avoid colliding with the
// ASN.1 keyword constants of those same names already in constants.go.
//
// The generic shapes that stood here - a VALUE of any, a LIST of those and
// a MAP keyed by name - are gone. Every node a rule builds is now one of
// the messages proto/ast.proto declares, and the %union names them, so a
// rule that builds the wrong one does not compile.
type (
	STR    string
	NUMBER float64
	BOOL   bool
	INT    int
)
%}

// line/col track the source position of the current token (used for error
// reporting; see Lexer.Error in lexer.go). The Type* fields hold the
// per-symbol value built up by grammar actions, one per shorthand type
// above.
// The per-symbol value a rule action builds. Every node is one of the
// messages proto/ast.proto declares, so a rule that builds the wrong one
// does not compile - which is a stronger guarantee than the generic map
// this held before, where a mistyped key was silently nothing.
%union {
	LINE        INT
	COLUMN      INT
	TypeToken   struct{}
	TypeString  STR
	TypeNumber  NUMBER
	TypeBoolean BOOL
	TypeStrings []string

	TypeModule               *ast.Module
	TypeAssignment           *ast.Assignment
	TypeType                 *ast.Type
	TypeValue                *ast.Value
	TypeExports              *ast.Exports
	TypeImports              *ast.Imports
	TypeSymbolsFromModule    *ast.SymbolsFromModule
	TypeSymbol               *ast.Symbol
	TypeObjIdComponent       *ast.ObjIdComponent
	TypeNamedNumber          *ast.NamedNumber
	TypeComponent            *ast.Component
	TypeElement              *ast.Element
	TypeConstraint           *ast.Constraint
	TypeElementSet           *ast.ElementSet
	TypeSetting              *ast.Setting
	TypeSyntaxToken          *ast.SyntaxToken
	TypeFieldSpec            *ast.FieldSpec
	TypeClass                *ast.Class
	TypeParameter            *ast.Parameter
	TypeAtNotation           *ast.AtNotation
	TypeTag                  *ast.Tag
	TypeException            *ast.Exception
	TypeNamedConstraint      *ast.NamedConstraint
	TypeSection              *ast.Section
	TypeEndpoint             *Endpoint
	TypeRange                *ast.Range
	TypeBuiltinType          *ast.BuiltinType
	TypeReferenceType        *ast.ReferenceType
	TypeSelectionType        *ast.SelectionType
	TypeFieldType            *ast.FieldType
	TypeBraced               *ast.Braced
	TypeValueBody            *ast.ValueBody
	TypeValueSetBody         *ast.ValueSetBody
	TypeNamedComponent       *ast.NamedComponent
	TypeGroup                *ast.Group
	TypeSyntaxGroup          *ast.SyntaxGroup
	TypeObjIdComponents      *ast.ObjIdComponents

	TypeAssignments           []*ast.Assignment
	TypeAtNotations           []*ast.AtNotation
	TypeComponents            []*ast.Component
	TypeConstraints           []*ast.Constraint
	TypeElementSets           []*ast.ElementSet
	TypeElements              []*ast.Element
	TypeFieldSpecs            []*ast.FieldSpec
	TypeModules               []*ast.Module
	TypeNamedConstraints      []*ast.NamedConstraint
	TypeNamedNumbers          []*ast.NamedNumber
	TypeArcs                  []*ast.ObjIdComponent
	TypeParameters            []*ast.Parameter
	TypeSections              []*ast.Section
	TypeSettings              []*ast.Setting
	TypeSymbols               []*ast.Symbol
	TypeSymbolsFromModules    []*ast.SymbolsFromModule
	TypeSyntaxTokens          []*ast.SyntaxToken
	TypeTags                  []*ast.Tag
	TypeValues                []*ast.Value
}

// Keyword tokens, one per ASN.1 reserved word (X.680 clause 12.38). They
// are prefixed with TOK_ to avoid colliding with the string constants of
// the same base name in constants.go (e.g. ABSENT vs TOK_ABSENT), which is
// what KEYWORD_TOKENS maps to them.
%token TOK_ABSENT
%token TOK_ABSTRACT_SYNTAX
%token TOK_ALL
%token TOK_APPLICATION
%token TOK_AUTOMATIC
%token TOK_BEGIN
%token TOK_BIT
%token TOK_BMP_STRING
%token TOK_BOOLEAN
%token TOK_BY
%token TOK_CHARACTER
%token TOK_CHOICE
%token TOK_CLASS
%token TOK_COMPONENT
%token TOK_COMPONENTS
%token TOK_CONSTRAINED
%token TOK_CONTAINING
%token TOK_DATE
%token TOK_DATE_TIME
%token TOK_DEFAULT
%token TOK_DEFINITIONS
%token TOK_DURATION
%token TOK_EMBEDDED
%token TOK_ENCODED
%token TOK_ENCODING_CONTROL
%token TOK_END
%token TOK_ENUMERATED
%token TOK_EXCEPT
%token TOK_EXPLICIT
%token TOK_EXPORTS
%token TOK_EXTENSIBILITY
%token TOK_EXTERNAL
%token TOK_FALSE
%token TOK_FROM
%token TOK_GENERALIZED_TIME
%token TOK_GENERAL_STRING
%token TOK_GRAPHIC_STRING
%token TOK_IA5_STRING
%token TOK_IDENTIFIER
%token TOK_IMPLICIT
%token TOK_IMPLIED
%token TOK_IMPORTS
%token TOK_INCLUDES
%token TOK_INSTANCE
%token TOK_INSTRUCTIONS
%token TOK_INTEGER
%token TOK_INTERSECTION
%token TOK_ISO646_STRING
%token TOK_MAX
%token TOK_MIN
%token TOK_MINUS_INFINITY
%token TOK_NOT_A_NUMBER
%token TOK_NULL
%token TOK_NUMERIC_STRING
%token TOK_OBJECT
%token TOK_OBJECT_DESCRIPTOR
%token TOK_OCTET
%token TOK_OF
%token TOK_OID_IRI
%token TOK_OPTIONAL
%token TOK_PATTERN
%token TOK_PDV
%token TOK_PLUS_INFINITY
%token TOK_PRESENT
%token TOK_PRINTABLE_STRING
%token TOK_PRIVATE
%token TOK_REAL
%token TOK_RELATIVE_OID
%token TOK_RELATIVE_OID_IRI
%token TOK_SEQUENCE
%token TOK_SET
%token TOK_SETTINGS
%token TOK_SIZE
%token TOK_STRING
%token TOK_SYNTAX
%token TOK_T61_STRING
%token TOK_TAGS
%token TOK_TELETEX_STRING
%token TOK_TIME
%token TOK_TIME_OF_DAY
%token TOK_TRUE
%token TOK_TYPE_IDENTIFIER
%token TOK_UNION
%token TOK_UNIQUE
%token TOK_UNIVERSAL
%token TOK_UNIVERSAL_STRING
%token TOK_UTC_TIME
%token TOK_UTF8_STRING
%token TOK_VIDEOTEX_STRING
%token TOK_VISIBLE_STRING
%token TOK_WITH

// Named lexical items (X.680 clause 12 / X.681 clause 7). These carry the
// text the lexer matched, so they are declared with the union field that
// holds it; the two number forms carry the parsed value instead, which is
// what the lexer fills in for them.
%token <TypeString> TOK_IDENT
%token <TypeString> TOK_TYPEREF
%token <TypeString> TOK_BSTR
%token <TypeString> TOK_HSTR
%token <TypeString> TOK_CSTR
%token <TypeString> TOK_TYPEFIELDREF
%token <TypeString> TOK_VALUEFIELDREF
%token <TypeNumber> TOK_NUM
%token <TypeNumber> TOK_REALNUM

// A balanced brace group whose contents cannot be a value, returned whole
// by the lexer (see _LexBraces there). X.681's objects are written where
// values are, and which was meant is the class's to say, so a group that
// is plainly not a value is kept as the text a later pass will read.
%token <TypeString> TOK_BRACES

// The brace that opens X.682's at-notation, "{@id}". Nothing else in
// ASN.1 is a brace followed by an at sign, so the lexer gives this one a
// token of its own and the component relation constraint below needs no
// lookahead (see _LexAtBrace there).
%token <TypeString> TOK_AT_BRACE

// The body of an encoding control section, returned whole by the lexer
// (see _LexInstructions there). X.680 clause 54 hands a section's
// contents to the encoding it names, so there is nothing here to parse
// and the text is kept for whoever reads that encoding.
%token <TypeString> TOK_ASSIGNED_IDENT

%token <TypeString> TOK_ENCODING_PREFIX

%token <TypeString> TOK_INSTRUCTIONS_BODY

// A whole XML typed value, returned by the lexer (see _LexXMLValue
// there). What an XML element holds is not ASN.1 - X.680 gives it its own
// lexical items - so the element is kept as the text it is, for the pass
// that knows the type it was written for.
%token <TypeString> TOK_XML_VALUE

// Punctuation tokens. goyacc would let a single character be written as
// itself in a rule, which is its usual convention, but every one of them
// is named here instead: a rule that reads TOK_COMMA says what it means,
// and nothing in the file is then a bare quoted character.
%token TOK_ASSIGNMENT
%token TOK_RANGE_SEPARATOR
%token TOK_ELLIPSIS
%token TOK_LEFT_VERSION_BRACKETS
%token TOK_RIGHT_VERSION_BRACKETS
%token TOK_XML_END_TAG_START
%token TOK_XML_SINGLE_TAG_END
%token TOK_EXCLAMATION_MARK
%token TOK_LEFT_PARENTHESIS
%token TOK_RIGHT_PARENTHESIS
%token TOK_COMMA
%token TOK_HYPHEN_MINUS
%token TOK_FULL_STOP
%token TOK_COLON
%token TOK_SEMICOLON
%token TOK_LESS_THAN_SIGN
%token TOK_COMMERCIAL_AT
%token TOK_LEFT_SQUARE_BRACKET
%token TOK_RIGHT_SQUARE_BRACKET
%token TOK_CIRCUMFLEX_ACCENT
%token TOK_LEFT_CURLY_BRACKET
%token TOK_VERTICAL_LINE
%token TOK_RIGHT_CURLY_BRACKET

%type <TypeModules> Modules
%type <TypeModule> Module
%type <TypeModule> ModuleIdentifier
%type <TypeModule> DefinitiveIdentification
%type <TypeModule> DefinitiveOIDandIRI
%type <TypeArcs> ObjectIdentifierValue
%type <TypeArcs> ObjIdComponentList
%type <TypeObjIdComponent> ObjIdComponent
%type <TypeObjIdComponent> NameAndNumberForm
%type <TypeNumber> NumberForm
%type <TypeString> NameForm
%type <TypeString> IRIValue
%type <TypeString> EncodingReferenceDefault
%type <TypeString> TagDefault
%type <TypeBoolean> ExtensionDefault
%type <TypeExports> Exports
%type <TypeExports> SymbolsExported
%type <TypeImports> Imports
%type <TypeImports> SymbolsImported
%type <TypeSymbolsFromModules> SymbolsFromModuleList
%type <TypeSymbolsFromModule> SymbolsFromModule
%type <TypeSymbolsFromModule> GlobalModuleReference
%type <TypeSymbolsFromModule> AssignedIdentifier
%type <TypeSymbols> SymbolList
%type <TypeSymbol> Symbol
%type <TypeString> SelectionOption
%type <TypeString> Reference
%type <TypeAssignments> Assignments
%type <TypeSections> EncodingControlSections
%type <TypeSection> EncodingControlSection
%type <TypeAssignments> AssignmentList
%type <TypeAssignment> Assignment
%type <TypeAssignment> TypeAssignment
%type <TypeType> Type
%type <TypeType> BuiltinType
%type <TypeType> IntegerType
%type <TypeType> BitStringType
%type <TypeType> ReferencedType
%type <TypeType> DefinedType
%type <TypeType> ExternalTypeReference
%type <TypeNamedNumbers> NamedNumberList
%type <TypeNamedNumber> NamedNumber
%type <TypeNamedNumbers> NamedBitList
%type <TypeNamedNumber> NamedBit
%type <TypeString> SimpleType
%type <TypeString> RestrictedCharacterStringType
%type <TypeString> UsefulType
%type <TypeString> DefinedValue
%type <TypeNumber> SignedNumber
%type <TypeAssignment> ValueAssignment
%type <TypeAssignment> XMLValueAssignment
%type <TypeValue> Value
%type <TypeValue> NonNullValue
%type <TypeValue> SettingValue
%type <TypeValue> BracedValue
%type <TypeElements> ElementValueList
%type <TypeElement> ElementValue
%type <TypeValues> ValueRun
%type <TypeString> Literal
%type <TypeSyntaxTokens> WithSyntaxSpec
%type <TypeSyntaxTokens> SyntaxList
%type <TypeSyntaxTokens> SyntaxTokenList
%type <TypeSyntaxToken> SyntaxToken
%type <TypeString> NumberValue
%type <TypeString> RealNumberValue
%type <TypeString> StringValue
%type <TypeType> SequenceType
%type <TypeType> SetType
%type <TypeType> SequenceOfType
%type <TypeType> SetOfType
%type <TypeType> ChoiceType
%type <TypeType> EnumeratedType
%type <TypeComponents> ComponentTypeLists
%type <TypeComponent> ComponentTypeEntry
%type <TypeComponents> ComponentTypeList
%type <TypeComponent> ComponentType
%type <TypeComponent> ExtensionAdditionGroup
%type <TypeComponents> AlternativeTypeLists
%type <TypeComponent> AlternativeTypeEntry
%type <TypeComponents> AlternativeTypeList
%type <TypeComponent> ExtensionAdditionAlternativesGroup
%type <TypeComponents> Enumerations
%type <TypeComponent> EnumerationEntry
%type <TypeComponent> EnumerationItem
%type <TypeNamedComponent> NamedType
%type <TypeNumber> VersionNumber
%type <TypeType> ConstrainableType
%type <TypeType> EnclosingType
%type <TypeType> TaggedType
%type <TypeType> EncodingPrefixedType
%type <TypeString> EncodingPrefix
%type <TypeException> ExceptionSpec
%type <TypeException> ExceptionIdentification
%type <TypeElementSet> ContentsConstraint
%type <TypeElementSet> UserDefinedConstraint
%type <TypeValue> DefaultSyntax
%type <TypeElements> FieldSettingList
%type <TypeElement> FieldSetting
%type <TypeAtNotations> ComponentRelation
%type <TypeAtNotations> AtNotationList
%type <TypeAtNotation> AtNotation
%type <TypeNumber> Level
%type <TypeNumber> Stops
%type <TypeStrings> ComponentIdList
%type <TypeString> ComponentId
%type <TypeSettings> UserDefinedConstraintParameters
%type <TypeSetting> UserDefinedConstraintParameter
%type <TypeType> SelectionType
%type <TypeAssignment> ValueSetTypeAssignment
%type <TypeConstraint> ValueSet
%type <TypeAssignment> ParameterizedAssignment
%type <TypeParameters> ParameterList
%type <TypeParameters> ParameterSeries
%type <TypeParameter> Parameter
%type <TypeString> DummyReference
%type <TypeSettings> ActualParameterList
%type <TypeSettings> ActualParameterSeries
%type <TypeSetting> ActualParameter
%type <TypeSetting> Setting
%type <TypeAssignment> ObjectClassAssignment
%type <TypeClass> ObjectClassDefn
%type <TypeString> UsefulObjectClassReference
%type <TypeFieldSpecs> FieldSpecList
%type <TypeFieldSpec> FieldSpec
%type <TypeFieldSpec> FieldGovernor
%type <TypeBoolean> FieldUnique
%type <TypeFieldSpec> FieldOptionality
%type <TypeStrings> FieldName
%type <TypeString> PrimitiveFieldName
%type <TypeType> ObjectClassFieldType
%type <TypeType> InstanceOfType
%type <TypeType> InformationFromObjects
%type <TypeType> ReferencedObjects
%type <TypeString> DefinedObjectClass
%type <TypeTag> Tag
%type <TypeValue> ClassNumber
%type <TypeString> TagMode
%type <TypeString> EncodingReference
%type <TypeTag> TagContent
%type <TypeString> Class
%type <TypeConstraints> Constraints
%type <TypeType> TypeWithConstraint
%type <TypeConstraint> Constraint
%type <TypeConstraint> ElementSetSpecs
%type <TypeElementSet> ElementSetSpec
%type <TypeElementSet> Unions
%type <TypeElementSet> Intersections
%type <TypeElementSet> IntersectionElements
%type <TypeElementSet> Elements
%type <TypeElementSet> SubtypeElements
%type <TypeElementSet> ValueRange
%type <TypeEndpoint> LowerEndpoint
%type <TypeEndpoint> UpperEndpoint
%type <TypeValue> LowerEndValue
%type <TypeValue> UpperEndValue
%type <TypeElementSet> SizeConstraint
%type <TypeElementSet> ContainedSubtype
%type <TypeElementSet> Exclusions
%type <TypeElementSet> InnerTypeConstraints
%type <TypeElementSet> MultipleTypeConstraints
%type <TypeNamedConstraints> TypeConstraints
%type <TypeNamedConstraint> NamedConstraint
%type <TypeConstraint> ValueConstraint
%type <TypeString> PresenceConstraint
%type <TypeConstraint> CollectionConstraint

%start Modules

%%

// Modules is the grammar's start symbol: one or more Module headers back to
// back (e.g. two separate modules defined in the same file). Its value
// accumulates into the slice of modules Module builds, and is handed back
// to the caller by storing it on the Lexer - via a type assertion on
// asn1lex, the lexer instance passed to asn1Parse - since asn1Parse only
// returns a pass/fail int and has no other way to hand results back.
// Declaring the %type of each symbol above means $$ and $N are already the
// union field that symbol's node lives in, so no field suffix is needed.
//
// Every action below closes with a Trace call naming the rule and which of
// its alternatives reduced, counted from the first one down the page, so a
// traced line is found by reading to the "#2" of the rule it names. The
// trace is off unless ASN1_TRACE is set (see trace.go). It is the cheapest
// way to see what a grammar change did: the reductions arrive innermost
// first, so a rule that matched text meant for another one shows up as a
// line in the wrong place long before the result is wrong.
Modules:
	Module
	{
		$$ = []*ast.Module{$1}
		asn1lex.(*Lexer).Result = $$
		Trace("Modules: #1", $$)
	}
	| Modules Module
	{
		$$ = append($1, $2)
		asn1lex.(*Lexer).Result = $$
		Trace("Modules: #2", $$)
	}
	;

// Module is X.680's ModuleDefinition. The three clauses between
// DEFINITIONS and "::=" are each separately omittable, and each one's
// empty alternative is reduced on a lookahead the other two cannot start
// with, which is what keeps the run of them unambiguous.
//
// What sits between BEGIN and END X.680 writes as
// "ModuleBody ::= Exports Imports AssignmentList | empty". That
// nonterminal is inlined here and its empty alternative dropped: Exports
// and Imports each already derive empty, so an empty ModuleBody would be a
// second way to derive the same thing, which is a reduce/reduce conflict
// rather than a second meaning. The AssignmentList comes next.
//
// ModuleIdentifier has already built the result map, so the clauses here
// only add to it.
Module:
	ModuleIdentifier TOK_DEFINITIONS EncodingReferenceDefault TagDefault
	ExtensionDefault TOK_ASSIGNMENT TOK_BEGIN Exports Imports Assignments
	EncodingControlSections TOK_END
	{
		module := $1
		module.EncodingReference = string($3)
		module.TagDefault = string($4)
		module.Extensibility = bool($5)
		module.Exports = $8
		module.Imports = $9
		module.Assignments = $10
		module.Sections = $11
		$$ = module
		Trace("Module: #1", $$)
	}
	;

// A modulereference is lexically a typereference, so TOK_TYPEREF is what
// the lexer returns for it. That token is declared %token <TypeString>, so
// $1 below is already the STR the lexer filled in (see the note on Modules
// above for why no field suffix is needed).
ModuleIdentifier:
	TOK_TYPEREF DefinitiveIdentification
	{
		module := $2
		module.ModuleName = string($1)
		$$ = module
		Trace("ModuleIdentifier: #1", $$)
	}
	;

// The IRI form is only reachable through an object identifier, so the
// decision between the two non-empty alternatives is a plain one-token
// one: after the closing brace, a cstring continues into
// DefinitiveOIDandIRI and anything else ends the identification here.
DefinitiveIdentification:
	// Empty
	{
		$$ = &ast.Module{}
		Trace("DefinitiveIdentification: #1", $$)
	}
	| ObjectIdentifierValue
	{
		$$ = &ast.Module{
			DefinitiveOid: $1,
		}
		Trace("DefinitiveIdentification: #2", $$)
	}
	| DefinitiveOIDandIRI
	{
		$$ = $1
		Trace("DefinitiveIdentification: #3", $$)
	}
	;

DefinitiveOIDandIRI:
	ObjectIdentifierValue IRIValue
	{
		$$ = &ast.Module{
			DefinitiveOid: $1,
			Iri:           string($2),
		}
		Trace("DefinitiveOIDandIRI: #1", $$)
	}
	;

// One rule serves all three places an object identifier is written out:
// a module's own identifier, the one an import assigns to the module it
// names, and an object identifier value in an assignment. X.680 writes
// the first as DefinitiveObjIdComponent and the others as ObjIdComponents,
// and the difference between them is that a definitive one may not name
// an arc with a value defined elsewhere (13.8). That is a rule about what
// a name means, not about which tokens may appear, so it belongs to the
// pass that resolves names and the three are one rule here.
ObjectIdentifierValue:
	TOK_LEFT_CURLY_BRACKET ObjIdComponentList TOK_RIGHT_CURLY_BRACKET
	{
		$$ = $2
		Trace("ObjectIdentifierValue: #1", $$)
	}
	;

// X.680 writes this list right-recursive. It is left-recursive here
// instead, which is the same language and the shape an LALR parser keeps
// on its stack in constant depth.
ObjIdComponentList:
	ObjIdComponent
	{
		$$ = []*ast.ObjIdComponent{$1}
		Trace("ObjIdComponentList: #1", $$)
	}
	| ObjIdComponentList ObjIdComponent
	{
		$$ = append($1, $2)
		Trace("ObjIdComponentList: #2", $$)
	}
	;

// A component that gives only one of the two halves leaves the other key
// out of the map, which is what ObjIdComponent's zero values stand for.
ObjIdComponent:
	NameForm
	{
		$$ = &ast.ObjIdComponent{
			Name: string($1),
		}
		Trace("ObjIdComponent: #1", $$)
	}
	| NumberForm
	{
		$$ = &ast.ObjIdComponent{
			Number: int64($1),
		}
		Trace("ObjIdComponent: #2", $$)
	}
	| NameAndNumberForm
	{
		$$ = $1
		Trace("ObjIdComponent: #3", $$)
	}
	;

NameAndNumberForm:
	NameForm TOK_LEFT_PARENTHESIS NumberForm TOK_RIGHT_PARENTHESIS
	{
		$$ = &ast.ObjIdComponent{
			Name:   string($1),
			Number: int64($3),
		}
		Trace("NameAndNumberForm: #1", $$)
	}
	;

NameForm:
	TOK_IDENT
	{
		$$ = $1
		Trace("NameForm: #1", $$)
	}
	;

// The lexer has already parsed the lexeme into the NUMBER the union
// carries, so this rule only passes it along. NUMBER is a float64, which
// holds every arc a real object identifier uses exactly.
NumberForm:
	TOK_NUM
	{
		$$ = $1
		Trace("NumberForm: #1", $$)
	}
	;

// An IRI value is lexically a cstring - the arcs inside it are the
// lexeme's own business, not the grammar's - so it reaches the parser as
// one TOK_CSTR, quotes included.
IRIValue:
	TOK_CSTR
	{
		$$ = $1
		Trace("IRIValue: #1", $$)
	}
	;

// An encodingreference is a typereference written in upper case only. The
// lexer cannot tell the two apart, so TOK_INSTRUCTIONS following it is
// what distinguishes this clause, and the case rule is left to a later
// check against the name this keeps.
EncodingReferenceDefault:
	// Empty
	{
		$$ = ""
		Trace("EncodingReferenceDefault: #1", $$)
	}
	| TOK_TYPEREF TOK_INSTRUCTIONS
	{
		$$ = $1
		Trace("EncodingReferenceDefault: #2", $$)
	}
	;

// The keyword constants in constants.go are reused as this clause's value
// so the name a module wrote is the name the AST carries.
TagDefault:
	// Empty
	{
		$$ = ""
		Trace("TagDefault: #1", $$)
	}
	| TOK_EXPLICIT TOK_TAGS
	{
		$$ = EXPLICIT
		Trace("TagDefault: #2", $$)
	}
	| TOK_IMPLICIT TOK_TAGS
	{
		$$ = IMPLICIT
		Trace("TagDefault: #3", $$)
	}
	| TOK_AUTOMATIC TOK_TAGS
	{
		$$ = AUTOMATIC
		Trace("TagDefault: #4", $$)
	}
	;

ExtensionDefault:
	// Empty
	{
		$$ = false
		Trace("ExtensionDefault: #1", $$)
	}
	| TOK_EXTENSIBILITY TOK_IMPLIED
	{
		$$ = true
		Trace("ExtensionDefault: #2", $$)
	}
	;

// A module that writes no EXPORTS at all and one that writes "EXPORTS;"
// mean different things (X.680 13.13), so the absent clause yields nil -
// which reaches ToModule as a JSON null and leaves Module.Exports unset -
// while a clause that named nothing yields an empty map, giving an Exports
// node whose fields are all zero. ALL cannot be confused with a symbol,
// being a reserved word the lexer never returns as a typereference.
Exports:
	// Empty
	{
		$$ = nil
		Trace("Exports: #1", $$)
	}
	| TOK_EXPORTS TOK_ALL TOK_SEMICOLON
	{
		$$ = &ast.Exports{
			All: true,
		}
		Trace("Exports: #2", $$)
	}
	| TOK_EXPORTS SymbolsExported TOK_SEMICOLON
	{
		$$ = $2
		Trace("Exports: #3", $$)
	}
	;

SymbolsExported:
	// Empty
	{
		$$ = &ast.Exports{}
		Trace("SymbolsExported: #1", $$)
	}
	| SymbolList
	{
		$$ = &ast.Exports{
			Symbols: $1,
		}
		Trace("SymbolsExported: #2", $$)
	}
	;

// The same absent-versus-empty distinction Exports draws, for the reason
// X.680 13.16 d) and 13.17 give: "IMPORTS;" says the module names nothing
// from elsewhere, while no clause at all says only that the module
// predates the requirement to declare it.
Imports:
	// Empty
	{
		$$ = nil
		Trace("Imports: #1", $$)
	}
	| TOK_IMPORTS SymbolsImported TOK_SEMICOLON
	{
		$$ = $2
		Trace("Imports: #2", $$)
	}
	;

SymbolsImported:
	// Empty
	{
		$$ = &ast.Imports{}
		Trace("SymbolsImported: #1", $$)
	}
	| SymbolsFromModuleList
	{
		$$ = &ast.Imports{
			Modules: $1,
		}
		Trace("SymbolsImported: #2", $$)
	}
	;

SymbolsFromModuleList:
	SymbolsFromModule
	{
		$$ = []*ast.SymbolsFromModule{$1}
		Trace("SymbolsFromModuleList: #1", $$)
	}
	| SymbolsFromModuleList SymbolsFromModule
	{
		$$ = append($1, $2)
		Trace("SymbolsFromModuleList: #2", $$)
	}
	;

// GlobalModuleReference has already built the map this adds to, the same
// way ModuleIdentifier does for the header.
SymbolsFromModule:
	SymbolList TOK_FROM GlobalModuleReference SelectionOption
	{
		from := $3
		from.Symbols = $1
		from.SelectionOption = string($4)
		$$ = from
		Trace("SymbolsFromModule: #1", $$)
	}
	;

GlobalModuleReference:
	TOK_TYPEREF AssignedIdentifier
	{
		reference := $2
		reference.ModuleName = string($1)
		$$ = reference
		Trace("GlobalModuleReference: #1", $$)
	}
	;

// The object identifier a module is imported by: written out in braces, or
// named by a valuereference, or left out.
//
// The named form is why TOK_ASSIGNED_IDENT exists. After "FROM Other" an
// identifier is either this module's assigned identifier or the first
// symbol of the next SymbolsFromModule, and no rule can choose: X.680 knows
// the notation is ambiguous here and resolves it in prose rather than in
// the syntax (clause 11, NOTE). What decides is the token after - a symbol
// is followed by a comma or by FROM, an assigned identifier by anything
// else - which is one token past the one a parser must act on, so the lexer
// reads it and this rule needs no lookahead at all. See lib/review.md.
//
// The braced form reuses ObjectIdentifierValue because an assigned
// identifier is written the same way, arcs named by a DefinedValue
// included (X.680 32.3).
AssignedIdentifier:
	// Empty
	{
		$$ = &ast.SymbolsFromModule{}
		Trace("AssignedIdentifier: #1", $$)
	}
	| ObjectIdentifierValue
	{
		$$ = &ast.SymbolsFromModule{
			Assigned: &ast.SymbolsFromModule_Oid{
				Oid: &ast.ObjIdComponents{
					Arcs: $1,
				},
			},
		}
		Trace("AssignedIdentifier: #2", $$)
	}
	| TOK_ASSIGNED_IDENT
	{
		$$ = &ast.SymbolsFromModule{
			Assigned: &ast.SymbolsFromModule_Value{
				Value: string($1),
			},
		}
		Trace("AssignedIdentifier: #3", $$)
	}
	;

// SUCCESSORS and DESCENDANTS are not reserved words, so the lexer hands
// them over as an ordinary typereference and this rule is what holds them
// to the two X.680 allows. Reporting through the lexer rather than
// rejecting the parse keeps the position in the message and lets the rest
// of the module still be read.
SelectionOption:
	// Empty
	{
		$$ = ""
		Trace("SelectionOption: #1", $$)
	}
	| TOK_WITH TOK_TYPEREF
	{
		if $2 != SUCCESSORS && $2 != DESCENDANTS {
			expected := SUCCESSORS + " or " + DESCENDANTS
			asn1lex.Error("expected " + expected + " after " + WITH)
		}

		$$ = $2
		Trace("SelectionOption: #2", $$)
	}
	;

SymbolList:
	Symbol
	{
		$$ = []*ast.Symbol{$1}
		Trace("SymbolList: #1", $$)
	}
	| SymbolList TOK_COMMA Symbol
	{
		$$ = append($1, $3)
		Trace("SymbolList: #2", $$)
	}
	;

// X.683 writes the parameterized form as its own ParameterizedReference
// production. It is left-factored into the plain one here so the decision
// between them waits for the brace, rather than being made on the name
// that both start with.
Symbol:
	Reference
	{
		$$ = &ast.Symbol{
			Name: string($1),
		}
		Trace("Symbol: #1", $$)
	}
	| Reference TOK_LEFT_CURLY_BRACKET TOK_RIGHT_CURLY_BRACKET
	{
		$$ = &ast.Symbol{
			Name:          string($1),
			Parameterized: true,
		}
		Trace("Symbol: #2", $$)
	}
	;

// X.680 lists five kinds of reference here - for types, values, object
// classes, objects and object sets - but the lexer has only two tokens to
// tell them apart with, since the difference between the five is a
// spelling rule over the same two shapes. Writing all five would be five
// ways to reduce the same token, so the rule keeps the two shapes and
// leaves which kind a name denotes to the pass that knows what was
// declared.
Reference:
	TOK_TYPEREF
	{
		$$ = $1
		Trace("Reference: #1", $$)
	}
	| TOK_IDENT
	{
		$$ = $1
		Trace("Reference: #2", $$)
	}
	;

// X.680 has no rule of this name: a module with no assignments is reached
// through the empty alternative of ModuleBody, which is inlined away here
// (see Module). The optionality has to live somewhere, and it lives here
// so that AssignmentList below stays the non-empty list X.680 writes.
//
// Accepting a module that writes EXPORTS or IMPORTS and then no
// assignments is wider than X.680, which can only derive an empty body
// through the ModuleBody alternative that takes no clauses either. Every
// compiler accepts it and the alternative is to reject "BEGIN EXPORTS
// ALL; END" over a distinction nothing rests on. See lib/review.md.
// X.680 clause 54's encoding control sections, which close a module. Each
// names an encoding and then speaks that encoding's own notation, which
// X.680 does not define - so the body arrives as the one token the lexer
// made of it and is kept as text.
EncodingControlSections:
	// Empty
	{
		$$ = nil
		Trace("EncodingControlSections: #1", $$)
	}
	| EncodingControlSections EncodingControlSection
	{
		$$ = append($1, $2)
		Trace("EncodingControlSections: #2", $$)
	}
	;

EncodingControlSection:
	TOK_ENCODING_CONTROL TOK_TYPEREF TOK_INSTRUCTIONS_BODY
	{
		$$ = &ast.Section{
			EncodingReference: string($2),
			Text:              string($3),
		}
		Trace("EncodingControlSection: #1", $$)
	}
	;

Assignments:
	// Empty
	{
		$$ = nil
		Trace("Assignments: #1", $$)
	}
	| AssignmentList
	{
		$$ = $1
		Trace("Assignments: #2", $$)
	}
	;

AssignmentList:
	Assignment
	{
		$$ = []*ast.Assignment{$1}
		Trace("AssignmentList: #1", $$)
	}
	| AssignmentList Assignment
	{
		$$ = append($1, $2)
		Trace("AssignmentList: #2", $$)
	}
	;

// X.680 gives Assignment eight alternatives, and all eight are reached by
// the six below. A type assignment opens with a typereference and a value
// assignment with a valuereference, which are different tokens, so nothing
// has to be decided between those two.
//
// X.681's three - an object class, an object and an object set - are not
// alternatives of their own, and cannot be: an objectclassreference is
// lexically a typereference, so "FOO ::= ..." says nothing about which was
// meant, and the same holds for an objectreference against a
// valuereference. What does say is the right-hand side. ObjectClassAssignment
// is there because CLASS is a word only a class definition opens with; an
// object arrives as a value whose type is the class, and an object set as a
// value set, which is what ValueAssignment and ValueSetTypeAssignment
// already are. resolve.go has the class table that tells them apart.
Assignment:
	TypeAssignment
	{
		$$ = $1
		Trace("Assignment: #1", $$)
	}
	| ValueSetTypeAssignment
	{
		$$ = $1
		Trace("Assignment: #2", $$)
	}
	| ValueAssignment
	{
		$$ = $1
		Trace("Assignment: #3", $$)
	}
	| ParameterizedAssignment
	{
		$$ = $1
		Trace("Assignment: #4", $$)
	}
	| XMLValueAssignment
	{
		$$ = $1
		Trace("Assignment: #5", $$)
	}
	| ObjectClassAssignment
	{
		$$ = $1
		Trace("Assignment: #6", $$)
	}
	;

// An objectclassreference is lexically a typereference - X.681 7.2 only
// adds that it is written in capitals, which a typereference may be too -
// so "FOO ::= BAR" is a type assignment and an object class assignment
// alike, and no lookahead settles it. X.681 resolves that by what the
// names turn out to denote, which is a pass away from here.
//
// So this rule takes only the right-hand sides that cannot be a type: a
// CLASS definition, and the two classes X.681 gives every module.
// "FOO ::= BAR" stays a type assignment, and the resolver reclassifies it
// if BAR turns out to be a class. See lib/review.md.
ObjectClassAssignment:
	TOK_TYPEREF TOK_ASSIGNMENT ObjectClassDefn
	{
		$$ = &ast.Assignment{
			Name: string($1),
			Body: &ast.Assignment_Class{
				Class: $3,
			},
		}
		Trace("ObjectClassAssignment: #1", $$)
	}
	| TOK_TYPEREF TOK_ASSIGNMENT UsefulObjectClassReference
	{
		$$ = &ast.Assignment{
			Name: string($1),
			Body: &ast.Assignment_Class{
				Class: &ast.Class{
					Reference: string($3),
				},
			},
		}
		Trace("ObjectClassAssignment: #2", $$)
	}
	;

// X.681's class definition, with the syntax list its objects are written
// in. That list is made of words, and a word may be any run of capitals -
// including one ASN.1 has reserved for itself, since X.681 7.9 says a word
// is upper case and hyphens and says nothing about which are spoken for.
// The lexer reads every word-shaped lexeme inside these braces as a
// typereference for that reason, so Literal is one rule rather than a list
// of every reserved word a class might reach for.
ObjectClassDefn:
	TOK_CLASS TOK_LEFT_CURLY_BRACKET FieldSpecList TOK_RIGHT_CURLY_BRACKET WithSyntaxSpec
	{
		$$ = &ast.Class{
			Fields: $3,
			Syntax: $5,
		}
		Trace("ObjectClassDefn: #1", $$)
	}
	;

WithSyntaxSpec:
	// Empty
	{
		$$ = nil
		Trace("WithSyntaxSpec: #1", $$)
	}
	| TOK_WITH TOK_SYNTAX SyntaxList
	{
		$$ = $3
		Trace("WithSyntaxSpec: #2", $$)
	}
	;

// The notation a class declares for its own objects: the words a module
// must write, the fields it must fill in, and the groups it may leave
// out. X.681 10.5 NOTE 2 says a "[[" inside one of these is two brackets
// and not the version-bracket lexical item; this grammar does not make
// that distinction, so a group opened immediately inside another must be
// written with a space between the brackets.
SyntaxList:
	TOK_LEFT_CURLY_BRACKET SyntaxTokenList TOK_RIGHT_CURLY_BRACKET
	{
		$$ = $2
		Trace("SyntaxList: #1", $$)
	}
	;

SyntaxTokenList:
	SyntaxToken
	{
		$$ = []*ast.SyntaxToken{$1}
		Trace("SyntaxTokenList: #1", $$)
	}
	| SyntaxTokenList SyntaxToken
	{
		$$ = append($1, $2)
		Trace("SyntaxTokenList: #2", $$)
	}
	;

SyntaxToken:
	Literal
	{
		$$ = &ast.SyntaxToken{
			Kind: &ast.SyntaxToken_Literal{
				Literal: string($1),
			},
		}
		Trace("SyntaxToken: #1", $$)
	}
	| PrimitiveFieldName
	{
		$$ = &ast.SyntaxToken{
			Kind: &ast.SyntaxToken_Field{
				Field: string($1),
			},
		}
		Trace("SyntaxToken: #2", $$)
	}
	| TOK_LEFT_SQUARE_BRACKET SyntaxTokenList TOK_RIGHT_SQUARE_BRACKET
	{
		$$ = &ast.SyntaxToken{
			Kind: &ast.SyntaxToken_Group{
				Group: &ast.SyntaxGroup{
					Tokens: $2,
				},
			},
		}
		Trace("SyntaxToken: #3", $$)
	}
	;

// A word a class puts in its own syntax. Most are not reserved and reach
// the lexer as a typereference, which is the first alternative; the rest
// are the reserved words X.681 10.6 permits.
//
// That clause names the ones it forbids, and its NOTE says why the list
// is what it is: they are all and only the words that can begin a Type, a
// Value, a ValueSet, an Object or an ObjectSet, plus END. The reserved
// words that remain are therefore exactly those that cannot be mistaken
// for the start of a setting - which is what will let a literal sit
// beside a setting when the object notation arrives.
Literal:
	TOK_TYPEREF
	{
		$$ = $1
		Trace("Literal: #1", $$)
	}
	| TOK_COMMA
	{
		$$ = COMMA
		Trace("Literal: #2", $$)
	}
	;

UsefulObjectClassReference:
	TOK_TYPE_IDENTIFIER
	{
		$$ = TYPE_IDENTIFIER
		Trace("UsefulObjectClassReference: #1", $$)
	}
	| TOK_ABSTRACT_SYNTAX
	{
		$$ = ABSTRACT_SYNTAX
		Trace("UsefulObjectClassReference: #2", $$)
	}
	;

FieldSpecList:
	FieldSpec
	{
		$$ = []*ast.FieldSpec{$1}
		Trace("FieldSpecList: #1", $$)
	}
	| FieldSpecList TOK_COMMA FieldSpec
	{
		$$ = append($1, $3)
		Trace("FieldSpecList: #2", $$)
	}
	;

// X.681 gives seven kinds of field spec. There are two rules here,
// because there are two tokens: a field reference is "&Upper" or
// "&lower", and the specification's five primitive field names are those
// two shapes under five names - a type field and a value set field are
// both "&Upper", a value field and an object field are both "&lower".
//
// Which kind a field is then follows from its governor, and that is the
// resolver's to say as well: a governor of INTEGER makes "&id INTEGER" a
// fixed type value field, a governor naming a class makes "&obj FOO" an
// object field, and the grammar cannot tell those apart because a class
// reference is lexically a type reference.
FieldSpec:
	TOK_TYPEFIELDREF FieldGovernor FieldUnique FieldOptionality
	{
		field := $2
		field.Name = string($1)
		field.Unique = bool($3)
		field.Optional = $4.GetOptional()
		field.Default = $4.GetDefault()
		$$ = field
		Trace("FieldSpec: #1", $$)
	}
	| TOK_VALUEFIELDREF FieldGovernor FieldUnique FieldOptionality
	{
		field := $2
		field.Name = string($1)
		field.Unique = bool($3)
		field.Optional = $4.GetOptional()
		field.Default = $4.GetDefault()
		$$ = field
		Trace("FieldSpec: #2", $$)
	}
	;

// The governor is a type, a class - which is a type reference and so
// already a Type here - or the dotted name of another field this one
// takes its type from. A field reference begins the last, and nothing a
// Type may begin with does.
FieldGovernor:
	// Empty
	{
		$$ = &ast.FieldSpec{}
		Trace("FieldGovernor: #1", $$)
	}
	| Type
	{
		$$ = &ast.FieldSpec{
			Governor: $1,
		}
		Trace("FieldGovernor: #2", $$)
	}
	| FieldName
	{
		$$ = &ast.FieldSpec{
			Path: $1,
		}
		Trace("FieldGovernor: #3", $$)
	}
	| UsefulObjectClassReference
	{
		// X.681's object and object set field specs are governed by a
		// class rather than a type - "&AbstractSyntaxes ABSTRACT-SYNTAX".
		// A class named by a typereference is the Type above, since the
		// two are the same token; the two the specification defines
		// itself are reserved words and reach nothing else.
		$$ = &ast.FieldSpec{
			Governor: _Referenced("", string($1)),
		}
		Trace("FieldGovernor: #4", $$)
	}
	;

FieldUnique:
	// Empty
	{
		$$ = false
		Trace("FieldUnique: #1", $$)
	}
	| TOK_UNIQUE
	{
		$$ = true
		Trace("FieldUnique: #2", $$)
	}
	;

// X.681 writes one optionality spec per kind of field, differing in what
// DEFAULT takes - a type for a type field, a value for a value field, an
// object set for an object set field. They are one rule here for the same
// reason the field specs are, and DEFAULT takes a Setting, which is the
// union of all of them that a parser can express.
FieldOptionality:
	// Empty
	{
		$$ = &ast.FieldSpec{}
		Trace("FieldOptionality: #1", $$)
	}
	| TOK_OPTIONAL
	{
		$$ = &ast.FieldSpec{
			Optional: true,
		}
		Trace("FieldOptionality: #2", $$)
	}
	| TOK_DEFAULT Setting
	{
		$$ = &ast.FieldSpec{
			Default: $2,
		}
		Trace("FieldOptionality: #3", $$)
	}
	;

FieldName:
	PrimitiveFieldName
	{
		$$ = []string{string($1)}
		Trace("FieldName: #1", $$)
	}
	| FieldName TOK_FULL_STOP PrimitiveFieldName
	{
		$$ = append($1, string($3))
		Trace("FieldName: #2", $$)
	}
	;

PrimitiveFieldName:
	TOK_TYPEFIELDREF
	{
		$$ = $1
		Trace("PrimitiveFieldName: #1", $$)
	}
	| TOK_VALUEFIELDREF
	{
		$$ = $1
		Trace("PrimitiveFieldName: #2", $$)
	}
	;

// X.683's parameterized assignments differ from the three above by the
// brace after the name. Nothing else can begin there - no Type starts
// with a brace - so the parameter list is taken on that one token, and
// what follows it is the same choice the unparameterized forms make:
// "::=" names a type, and anything else begins the type a value or a
// value set is drawn from.
//
// The three that X.683 also lists - for object classes, objects and
// object sets - wait for X.681.
ParameterizedAssignment:
	TOK_TYPEREF ParameterList TOK_ASSIGNMENT Type
	{
		$$ = &ast.Assignment{
			Name:       string($1),
			Parameters: $2,
			Body:       &ast.Assignment_Type{
				Type: $4,
			},
		}
		Trace("ParameterizedAssignment: #1", $$)
	}
	| TOK_TYPEREF ParameterList Type TOK_ASSIGNMENT ValueSet
	{
		$$ = &ast.Assignment{
			Name:       string($1),
			Parameters: $2,
			Body: &ast.Assignment_ValueSet{
				ValueSet: &ast.ValueSetBody{
					Type: $3,
					Set:  $5,
				},
			},
		}
		Trace("ParameterizedAssignment: #2", $$)
	}
	| TOK_IDENT ParameterList Type TOK_ASSIGNMENT Value
	{
		$$ = &ast.Assignment{
			Name:       string($1),
			Parameters: $2,
			Body: &ast.Assignment_Value{
				Value: &ast.ValueBody{
					Type:  $3,
					Value: $5,
				},
			},
		}
		Trace("ParameterizedAssignment: #3", $$)
	}
	| TOK_TYPEREF ParameterList TOK_ASSIGNMENT ObjectClassDefn
	{
		$$ = &ast.Assignment{
			Name:       string($1),
			Parameters: $2,
			Body:       &ast.Assignment_Class{
				Class: $4,
			},
		}
		Trace("ParameterizedAssignment: #4", $$)
	}
	;

ParameterList:
	TOK_LEFT_CURLY_BRACKET ParameterSeries TOK_RIGHT_CURLY_BRACKET
	{
		$$ = $2
		Trace("ParameterList: #1", $$)
	}
	;

ParameterSeries:
	Parameter
	{
		$$ = []*ast.Parameter{$1}
		Trace("ParameterSeries: #1", $$)
	}
	| ParameterSeries TOK_COMMA Parameter
	{
		$$ = append($1, $3)
		Trace("ParameterSeries: #2", $$)
	}
	;

// A parameter is a name, or a governor and a name with a colon between
// them. Both begin with a reference, and the colon is what separates
// them: a bare name is reduced on the comma or the brace that ends it,
// where a governor carries on.
//
// X.683's Governor is a Type or a DefinedObjectClass. A class named by a
// typereference is the Type below, since the two are the same token; the
// two classes X.681 defines itself are reserved words and reach nothing
// else, so they have an alternative of their own.
Parameter:
	DummyReference
	{
		$$ = &ast.Parameter{
			Name: string($1),
		}
		Trace("Parameter: #1", $$)
	}
	| Type TOK_COLON DummyReference
	{
		$$ = &ast.Parameter{
			Governor: $1,
			Name:     string($3),
		}
		Trace("Parameter: #2", $$)
	}
	| UsefulObjectClassReference TOK_COLON DummyReference
	{
		$$ = &ast.Parameter{
			Governor: _Referenced("", string($1)),
			Name:     string($3),
		}
		Trace("Parameter: #3", $$)
	}
	;

DummyReference:
	Reference
	{
		$$ = $1
		Trace("DummyReference: #1", $$)
	}
	;

// X.680 writes an XML value assignment with no type between the name and
// the "::=", where an ordinary value assignment has one. That is the
// whole of what separates them, and it is one token: after a
// valuereference, "::=" begins an XML value and anything else begins the
// type the value belongs to.
XMLValueAssignment:
	TOK_IDENT TOK_ASSIGNMENT TOK_XML_VALUE
	{
		$$ = &ast.Assignment{
			Name: string($1),
			Body: &ast.Assignment_Value{
				Value: &ast.ValueBody{
					Value: &ast.Value{Kind: &ast.Value_Xml{
						Xml: string($3),
					}},
				},
			},
		}
		Trace("XMLValueAssignment: #1", $$)
	}
	;

// X.680 writes the value's type between the name and the value, so a
// value assignment carries both.
ValueAssignment:
	TOK_IDENT Type TOK_ASSIGNMENT Value
	{
		$$ = &ast.Assignment{
			Name: string($1),
			Body: &ast.Assignment_Value{
				Value: &ast.ValueBody{
					Type:  $2,
					Value: $4,
				},
			},
		}
		Trace("ValueAssignment: #1", $$)
	}
	| TOK_IDENT Type TOK_ASSIGNMENT TOK_TYPEREF TOK_FULL_STOP TOK_IDENT ActualParameterList
	{
		// The same, named by the module it came from.
		$$ = &ast.Assignment{
			Name: string($1),
			Body: &ast.Assignment_Value{
				Value: &ast.ValueBody{
					Type:  $2,
					Value: _Parameterized(string($4), string($6), $7),
				},
			},
		}
		Trace("ValueAssignment: #2", $$)
	}
	| TOK_IDENT Type TOK_ASSIGNMENT TOK_IDENT ActualParameterList
	{
		// X.683's ParameterizedObject as the whole of an assignment,
		// "chainedRead OPERATION ::= chained{read}". It is written on the
		// tokens rather than reached through Value for the reason
		// SubtypeElements gives: a value may stand in a run, and there a
		// name followed by braces is X.680's NamedValue as readily.
		$$ = &ast.Assignment{
			Name: string($1),
			Body: &ast.Assignment_Value{
				Value: &ast.ValueBody{
					Type:  $2,
					Value: _Parameterized("", string($4), $5),
				},
			},
		}
		Trace("ValueAssignment: #3", $$)
	}
	| TOK_IDENT UsefulObjectClassReference TOK_ASSIGNMENT Value
	{
		// X.681's ObjectAssignment, where the class is one of the two the
		// specification defines itself. Those are reserved words rather
		// than typereferences, so they never reach Type and the ordinary
		// alternative above cannot take them - which is also why this one
		// costs nothing: no Type begins with either word.
		$$ = &ast.Assignment{
			Name: string($1),
			Body: &ast.Assignment_Value{
				Value: &ast.ValueBody{
					Type:  _Referenced("", string($2)),
					Value: $4,
				},
			},
		}
		Trace("ValueAssignment: #4", $$)
	}
	;

TypeAssignment:
	TOK_TYPEREF TOK_ASSIGNMENT Type
	{
		$$ = &ast.Assignment{
			Name: string($1),
			Body: &ast.Assignment_Type{
				Type: $3,
			},
		}
		Trace("TypeAssignment: #1", $$)
	}
	;

// A type assignment and a value set type assignment both open with a
// typereference, and the token after it is what separates them: "::="
// begins the type a type assignment names, and anything else begins the
// type a value set is drawn from.
ValueSetTypeAssignment:
	TOK_TYPEREF Type TOK_ASSIGNMENT ValueSet
	{
		$$ = &ast.Assignment{
			Name: string($1),
			Body: &ast.Assignment_ValueSet{
				ValueSet: &ast.ValueSetBody{
					Type: $2,
					Set:  $4,
				},
			},
		}
		Trace("ValueSetTypeAssignment: #1", $$)
	}
	| TOK_TYPEREF UsefulObjectClassReference TOK_ASSIGNMENT ValueSet
	{
		// X.681's ObjectSetAssignment over one of the specification's own
		// classes, for the reason ValueAssignment gives.
		$$ = &ast.Assignment{
			Name: string($1),
			Body: &ast.Assignment_ValueSet{
				ValueSet: &ast.ValueSetBody{
					Type: _Referenced("", string($2)),
					Set:  $4,
				},
			},
		}
		Trace("ValueSetTypeAssignment: #2", $$)
	}
	;

// The same set expression a constraint holds, written between braces.
ValueSet:
	TOK_LEFT_CURLY_BRACKET ElementSetSpecs TOK_RIGHT_CURLY_BRACKET
	{
		$$ = $2
		Trace("ValueSet: #1", $$)
	}
	;

// The tagged types of X.680 clause 31 are the one built-in form still
// missing from what a Type may be.
//
// X.680 writes "ConstrainedType ::= Type Constraint", which makes a
// constraint something that follows a whole type. Written that way the
// grammar is ambiguous, and in one place that matters: in
// "SEQUENCE OF INTEGER (1..10)" the constraint reads as the element's or
// as the collection's, and a parser deciding on one token cannot tell.
// Yacc would settle it by shifting, which happens to give the reading
// X.680 intends - but silently, and only by the luck of the default.
//
// So the constraints are a suffix on the type they bind to, and the two
// collection forms are kept out of what may take one. A constraint then
// binds to the innermost type that can hold it, which is the reading
// every implementation gives it, and the grammar says so rather than
// leaving it to a default. Constraining the collection is still written
// the way X.680 provides for: "SEQUENCE (SIZE (1..4)) OF INTEGER".
// See lib/review.md.
Type:
	ConstrainableType Constraints
	{
		result := $1
		result.Constraints = append(result.Constraints, $2...)
		$$ = result
		Trace("Type: #1", $$)
	}
	| EnclosingType
	{
		$$ = $1
		Trace("Type: #2", $$)
	}
	;

ConstrainableType:
	BuiltinType
	{
		$$ = $1
		Trace("ConstrainableType: #1", $$)
	}
	| ReferencedType
	{
		$$ = $1
		Trace("ConstrainableType: #2", $$)
	}
	;

// The forms written around another type, which has already taken any
// constraint that followed - so that one more would have nowhere to bind
// but the enclosing type, which is the ambiguity above. A tagged type is
// one of these for the same reason the collections are: in
// "[0] INTEGER (1..10)" the constraint is the INTEGER's.
EnclosingType:
	SequenceOfType
	{
		$$ = $1
		Trace("EnclosingType: #1", $$)
	}
	| SetOfType
	{
		$$ = $1
		Trace("EnclosingType: #2", $$)
	}
	| TypeWithConstraint
	{
		$$ = $1
		Trace("EnclosingType: #3", $$)
	}
	| TaggedType
	{
		$$ = $1
		Trace("EnclosingType: #4", $$)
	}
	| EncodingPrefixedType
	{
		$$ = $1
		Trace("EnclosingType: #5", $$)
	}
	| SelectionType
	{
		$$ = $1
		Trace("EnclosingType: #6", $$)
	}
	;

// X.680 lists this and InstanceOfType among the built-in types, and they
// sit there rather than with the enclosing types (see Type) because
// neither holds a type that could take a constraint written after it. A
// constraint after "FOO.&id" is the field's own, which is how every table
// constraint in a specification is written.
//
// A field of a class, "FOO.&Type". The token after the full stop is what
// separates this from an external type reference and from a value
// qualified by its module: a field reference begins one, a type
// reference the second and a value reference the third.
ObjectClassFieldType:
	TOK_TYPEREF TOK_FULL_STOP FieldName
	{
		$$ = _Field("", string($1), $3)
		Trace("ObjectClassFieldType: #1", $$)
	}
	| UsefulObjectClassReference TOK_FULL_STOP FieldName
	{
		$$ = _Field("", string($1), $3)
		Trace("ObjectClassFieldType: #2", $$)
	}
	| TOK_TYPEREF ActualParameterList TOK_FULL_STOP FieldName
	{
		field := _Field("", string($1), $4)
		field.GetField().Arguments = $2
		$$ = field
		Trace("ObjectClassFieldType: #3", $$)
	}
	| ExternalTypeReference TOK_FULL_STOP FieldName
	{
		reference := $1.GetReference()
		$$ = _Field(reference.GetModule(), reference.GetName(), $3)
		Trace("ObjectClassFieldType: #4", $$)
	}
	;

InstanceOfType:
	TOK_INSTANCE TOK_OF DefinedObjectClass
	{
		instance := _Builtin(INSTANCE_OF)
		instance.GetBuiltin().Element = _Referenced("", string($3))
		$$ = instance
		Trace("InstanceOfType: #1", $$)
	}
	;

DefinedObjectClass:
	TOK_TYPEREF
	{
		$$ = $1
		Trace("DefinedObjectClass: #1", $$)
	}
	| UsefulObjectClassReference
	{
		$$ = $1
		Trace("DefinedObjectClass: #2", $$)
	}
	;

// A tag is recorded on the type it tags rather than wrapping it in a node
// of its own, so a type that is tagged twice carries two tags. They are
// kept outermost first, which is the order they were written in.
// X.680 writes this as three productions, one per tagging mode. The mode
// is its own empty-able rule here instead, which is the same language
// written once: neither IMPLICIT nor EXPLICIT can begin a Type, so the
// empty alternative is reduced on anything that can.
TaggedType:
	Tag TagMode Type
	{
		tag := $1
		tag.Mode = string($2)

		tagged := $3
		tagged.Tags = append([]*ast.Tag{tag}, tagged.GetTags()...)
		$$ = tagged
		Trace("TaggedType: #1", $$)
	}
	;

// X.680 31's other prefixed type. A prefix is recorded on the type the way
// a tag is, outermost first, because a type may carry both and one of each
// per encoding-rules standard that has something to say about it.
//
// The prefix arrives as one token. Its content is an encoding instruction,
// which X.680 gives no production for at all - each encoding-rules standard
// defines its own - so there is nothing here to write it from, and the lexer
// keeps the brackets and everything between them; see _LexPrefix.
EncodingPrefixedType:
	EncodingPrefix Type
	{
		prefixed := $2
		prefixed.Prefixes = append([]string{string($1)}, prefixed.GetPrefixes()...)
		$$ = prefixed
		Trace("EncodingPrefixedType: #1", $$)
	}
	;

EncodingPrefix:
	TOK_ENCODING_PREFIX
	{
		$$ = $1
		Trace("EncodingPrefix: #1", $$)
	}
	;

TagMode:
	// Empty
	{
		$$ = ""
		Trace("TagMode: #1", $$)
	}
	| TOK_IMPLICIT
	{
		$$ = IMPLICIT
		Trace("TagMode: #2", $$)
	}
	| TOK_EXPLICIT
	{
		$$ = EXPLICIT
		Trace("TagMode: #3", $$)
	}
	;

Tag:
	TOK_LEFT_SQUARE_BRACKET TagContent TOK_RIGHT_SQUARE_BRACKET
	{
		$$ = $2
		Trace("Tag: #1", $$)
	}
	;

// What a tag holds. X.680 writes it as an optional encoding reference, an
// optional class and a number, and writing those two optional parts as
// rules that may be empty is what a parser cannot do here: a tag number
// may be a valuereference the module it came from qualifies, so "[Mod.tag]"
// and "[ENC: 0]" both open with a typereference, and an empty reference
// would have to be reduced before that typereference is read - one token
// before the colon or the full stop that says which was meant.
//
// So the four ways a tag may be written are written out. Each begins by
// shifting, the two that open with a typereference part on the token after
// it, and neither optional part is a rule that may be empty.
TagContent:
	ClassNumber
	{
		$$ = &ast.Tag{
			Number: $1,
		}
		Trace("TagContent: #1", $$)
	}
	| Class ClassNumber
	{
		$$ = &ast.Tag{
			Class:  string($1),
			Number: $2,
		}
		Trace("TagContent: #2", $$)
	}
	| EncodingReference ClassNumber
	{
		$$ = &ast.Tag{
			EncodingReference: string($1),
			Number:            $2,
		}
		Trace("TagContent: #3", $$)
	}
	| EncodingReference Class ClassNumber
	{
		$$ = &ast.Tag{
			EncodingReference: string($1),
			Class:             string($2),
			Number:            $3,
		}
		Trace("TagContent: #4", $$)
	}
	;

EncodingReference:
	TOK_TYPEREF TOK_COLON
	{
		$$ = $1
		Trace("EncodingReference: #1", $$)
	}
	;

// A tag that names no class is context-specific, which X.680 writes as an
// empty alternative here and TagContent writes as the alternatives that
// leave this rule out.
Class:
	TOK_UNIVERSAL
	{
		$$ = UNIVERSAL
		Trace("Class: #1", $$)
	}
	| TOK_APPLICATION
	{
		$$ = APPLICATION
		Trace("Class: #2", $$)
	}
	| TOK_PRIVATE
	{
		$$ = PRIVATE
		Trace("Class: #3", $$)
	}
	;

ClassNumber:
	TOK_NUM
	{
		$$ = _Number(string($<TypeString>1))
		Trace("ClassNumber: #1", $$)
	}
	| TOK_IDENT
	{
		$$ = _Named(string($1))
		Trace("ClassNumber: #2", $$)
	}
	| TOK_TYPEREF TOK_FULL_STOP TOK_IDENT
	{
		$$ = _Named(string($1) + FULL_STOP + string($3))
		Trace("ClassNumber: #3", $$)
	}
	;

Constraints:
	// Empty
	{
		$$ = nil
		Trace("Constraints: #1", $$)
	}
	| Constraints Constraint
	{
		$$ = append($1, $2)
		Trace("Constraints: #2", $$)
	}
	;

BuiltinType:
	SimpleType
	{
		$$ = _Builtin(string($1))
		Trace("BuiltinType: #1", $$)
	}
	| IntegerType
	{
		$$ = $1
		Trace("BuiltinType: #2", $$)
	}
	| BitStringType
	{
		$$ = $1
		Trace("BuiltinType: #3", $$)
	}
	| SequenceType
	{
		$$ = $1
		Trace("BuiltinType: #4", $$)
	}
	| SetType
	{
		$$ = $1
		Trace("BuiltinType: #5", $$)
	}
	| ChoiceType
	{
		$$ = $1
		Trace("BuiltinType: #6", $$)
	}
	| EnumeratedType
	{
		$$ = $1
		Trace("BuiltinType: #7", $$)
	}
	| ObjectClassFieldType
	{
		$$ = $1
		Trace("BuiltinType: #8", $$)
	}
	| InstanceOfType
	{
		$$ = $1
		Trace("BuiltinType: #9", $$)
	}
	| InformationFromObjects
	{
		$$ = $1
		Trace("BuiltinType: #10", $$)
	}
	;

// X.681 clause 15: a type, a value or a set taken from an object or an
// object set by naming one of its fields. The specification writes six
// productions for it - ValueFromObject, TypeFromObject and four more -
// which differ in what the field turns out to hold and not in a token, so
// they are one rule here and which of the six it was is the resolver's to
// say.
//
// The object-set form, "Ies.&field", is a typereference and a field name,
// which is ObjectClassFieldType's shape exactly; the two are told apart by
// whether the name is a class or a set, and that is a question about names.
// This rule is the other form, where the name is an object and so begins
// with a lower-case letter.
//
// X.681 makes it a value as readily as a type - ValueFromObject and
// TypeFromObject are the same tokens - and writing both is two reductions
// of one input wherever a setting may be either, which is an actual
// parameter and the inside of an object. So it is a type here and the
// resolver says what the field actually holds, which is the same answer
// NULL gets for the same reason (see Setting, and lib/review.md).
InformationFromObjects:
	ReferencedObjects TOK_FULL_STOP FieldName
	{
		referenced := $1
		referenced.GetField().Field = $3
		$$ = referenced
		Trace("InformationFromObjects: #1", $$)
	}
	;

// What a field is taken from. X.681 lists four - an object, an object set,
// and either of them with actual parameters - and the two that begin with
// a typereference are ObjectClassFieldType's own shape, so they are
// reached there. What is left is the object, which a lower-case name makes
// unmistakable, and X.683's ParameterizedObject, which is that name with
// an actual parameter list after it.
//
// This is the one place the parameter list can be taken. A name followed
// by braces is also X.680's NamedValue - a component name and the braced
// value set for it - so anywhere a value may stand the two readings are
// the same tokens, and the named value is the one every SEQUENCE value in
// testdata is written with. Here the field name after the dot says an
// object was meant, so nothing has to be guessed.
ReferencedObjects:
	TOK_IDENT
	{
		$$ = _Field("", string($1), nil)
		Trace("ReferencedObjects: #1", $$)
	}
	| TOK_TYPEREF TOK_FULL_STOP TOK_IDENT
	{
		$$ = _Field(string($1), string($3), nil)
		Trace("ReferencedObjects: #2", $$)
	}
	;

// The built-in types that are a keyword and nothing else. X.680 gives
// each its own one-line production - BooleanType, NullType, RealType and
// the rest - and they are one rule here because they differ only in the
// word, so writing them out separately would bury the two below that
// actually carry something.
SimpleType:
	TOK_BOOLEAN
	{
		$$ = BOOLEAN
		Trace("SimpleType: #1", $$)
	}
	| TOK_NULL
	{
		$$ = NULL
		Trace("SimpleType: #2", $$)
	}
	| TOK_REAL
	{
		$$ = REAL
		Trace("SimpleType: #3", $$)
	}
	| TOK_OBJECT TOK_IDENTIFIER
	{
		$$ = OBJECT_IDENTIFIER
		Trace("SimpleType: #4", $$)
	}
	| TOK_OCTET TOK_STRING
	{
		$$ = OCTET_STRING
		Trace("SimpleType: #5", $$)
	}
	| TOK_RELATIVE_OID
	{
		$$ = RELATIVE_OID
		Trace("SimpleType: #6", $$)
	}
	| TOK_OID_IRI
	{
		$$ = OID_IRI
		Trace("SimpleType: #7", $$)
	}
	| TOK_RELATIVE_OID_IRI
	{
		$$ = RELATIVE_OID_IRI
		Trace("SimpleType: #8", $$)
	}
	| TOK_EXTERNAL
	{
		$$ = EXTERNAL
		Trace("SimpleType: #9", $$)
	}
	| TOK_EMBEDDED TOK_PDV
	{
		$$ = EMBEDDED_PDV
		Trace("SimpleType: #10", $$)
	}
	| TOK_TIME
	{
		$$ = TIME
		Trace("SimpleType: #11", $$)
	}
	| TOK_DATE
	{
		$$ = DATE
		Trace("SimpleType: #12", $$)
	}
	| TOK_TIME_OF_DAY
	{
		$$ = TIME_OF_DAY
		Trace("SimpleType: #13", $$)
	}
	| TOK_DATE_TIME
	{
		$$ = DATE_TIME
		Trace("SimpleType: #14", $$)
	}
	| TOK_DURATION
	{
		$$ = DURATION
		Trace("SimpleType: #15", $$)
	}
	| TOK_CHARACTER TOK_STRING
	{
		$$ = CHARACTER_STRING
		Trace("SimpleType: #16", $$)
	}
	| RestrictedCharacterStringType
	{
		$$ = $1
		Trace("SimpleType: #17", $$)
	}
	| UsefulType
	{
		$$ = $1
		Trace("SimpleType: #18", $$)
	}
	;

RestrictedCharacterStringType:
	TOK_BMP_STRING
	{
		$$ = BMP_STRING
		Trace("RestrictedCharacterStringType: #1", $$)
	}
	| TOK_GENERAL_STRING
	{
		$$ = GENERAL_STRING
		Trace("RestrictedCharacterStringType: #2", $$)
	}
	| TOK_GRAPHIC_STRING
	{
		$$ = GRAPHIC_STRING
		Trace("RestrictedCharacterStringType: #3", $$)
	}
	| TOK_IA5_STRING
	{
		$$ = IA5_STRING
		Trace("RestrictedCharacterStringType: #4", $$)
	}
	| TOK_ISO646_STRING
	{
		$$ = ISO646_STRING
		Trace("RestrictedCharacterStringType: #5", $$)
	}
	| TOK_NUMERIC_STRING
	{
		$$ = NUMERIC_STRING
		Trace("RestrictedCharacterStringType: #6", $$)
	}
	| TOK_PRINTABLE_STRING
	{
		$$ = PRINTABLE_STRING
		Trace("RestrictedCharacterStringType: #7", $$)
	}
	| TOK_TELETEX_STRING
	{
		$$ = TELETEX_STRING
		Trace("RestrictedCharacterStringType: #8", $$)
	}
	| TOK_T61_STRING
	{
		$$ = T61_STRING
		Trace("RestrictedCharacterStringType: #9", $$)
	}
	| TOK_UNIVERSAL_STRING
	{
		$$ = UNIVERSAL_STRING
		Trace("RestrictedCharacterStringType: #10", $$)
	}
	| TOK_UTF8_STRING
	{
		$$ = UTF8_STRING
		Trace("RestrictedCharacterStringType: #11", $$)
	}
	| TOK_VIDEOTEX_STRING
	{
		$$ = VIDEOTEX_STRING
		Trace("RestrictedCharacterStringType: #12", $$)
	}
	| TOK_VISIBLE_STRING
	{
		$$ = VISIBLE_STRING
		Trace("RestrictedCharacterStringType: #13", $$)
	}
	;

// X.680 files these three under ReferencedType, as typereferences that
// every module may use without importing them. They cannot reach this
// grammar that way, because clause 12.38 also reserves all three words,
// so the lexer returns each as its own keyword and the parser sees a
// built-in type. The AST says built-in for the same reason.
UsefulType:
	TOK_GENERALIZED_TIME
	{
		$$ = GENERALIZED_TIME
		Trace("UsefulType: #1", $$)
	}
	| TOK_UTC_TIME
	{
		$$ = UTC_TIME
		Trace("UsefulType: #2", $$)
	}
	| TOK_OBJECT_DESCRIPTOR
	{
		$$ = OBJECT_DESCRIPTOR
		Trace("UsefulType: #3", $$)
	}
	;

IntegerType:
	TOK_INTEGER
	{
		$$ = _Builtin(INTEGER)
		Trace("IntegerType: #1", $$)
	}
	| TOK_INTEGER TOK_LEFT_CURLY_BRACKET NamedNumberList TOK_RIGHT_CURLY_BRACKET
	{
		$$ = &ast.Type{
			Kind: &ast.Type_Builtin{
				Builtin: &ast.BuiltinType{
					Name:  INTEGER,
					Named: $3,
				},
			},
		}
		Trace("IntegerType: #2", $$)
	}
	;

BitStringType:
	TOK_BIT TOK_STRING
	{
		$$ = _Builtin(BIT_STRING)
		Trace("BitStringType: #1", $$)
	}
	| TOK_BIT TOK_STRING TOK_LEFT_CURLY_BRACKET NamedBitList TOK_RIGHT_CURLY_BRACKET
	{
		$$ = &ast.Type{
			Kind: &ast.Type_Builtin{
				Builtin: &ast.BuiltinType{
					Name:  BIT_STRING,
					Named: $4,
				},
			},
		}
		Trace("BitStringType: #2", $$)
	}
	;

NamedNumberList:
	NamedNumber
	{
		$$ = []*ast.NamedNumber{$1}
		Trace("NamedNumberList: #1", $$)
	}
	| NamedNumberList TOK_COMMA NamedNumber
	{
		$$ = append($1, $3)
		Trace("NamedNumberList: #2", $$)
	}
	;

// The number and the named value are told apart by the token after the
// parenthesis, which is why both alternatives can be written out rather
// than left-factored: a number or a minus sign begins one, a name begins
// the other, and neither begins both.
NamedNumber:
	TOK_IDENT TOK_LEFT_PARENTHESIS SignedNumber TOK_RIGHT_PARENTHESIS
	{
		$$ = &ast.NamedNumber{
			Name:  string($1),
			Value: &ast.NamedNumber_Number{
				Number: int64($3),
			},
		}
		Trace("NamedNumber: #1", $$)
	}
	| TOK_IDENT TOK_LEFT_PARENTHESIS DefinedValue TOK_RIGHT_PARENTHESIS
	{
		$$ = &ast.NamedNumber{
			Name:  string($1),
			Value: &ast.NamedNumber_Reference{
				Reference: string($3),
			},
		}
		Trace("NamedNumber: #2", $$)
	}
	;

SignedNumber:
	TOK_NUM
	{
		$$ = $1
		Trace("SignedNumber: #1", $$)
	}
	| TOK_HYPHEN_MINUS TOK_NUM
	{
		$$ = -$2
		Trace("SignedNumber: #2", $$)
	}
	;

NamedBitList:
	NamedBit
	{
		$$ = []*ast.NamedNumber{$1}
		Trace("NamedBitList: #1", $$)
	}
	| NamedBitList TOK_COMMA NamedBit
	{
		$$ = append($1, $3)
		Trace("NamedBitList: #2", $$)
	}
	;

// A named bit differs from a named number in one thing: a bit position
// cannot be negative, so this takes a number where NamedNumber takes a
// SignedNumber. The two rules are kept apart for that one difference,
// because folding them would make the grammar accept a negative bit.
NamedBit:
	TOK_IDENT TOK_LEFT_PARENTHESIS TOK_NUM TOK_RIGHT_PARENTHESIS
	{
		$$ = &ast.NamedNumber{
			Name:  string($1),
			Value: &ast.NamedNumber_Number{
				Number: int64($3),
			},
		}
		Trace("NamedBit: #1", $$)
	}
	| TOK_IDENT TOK_LEFT_PARENTHESIS DefinedValue TOK_RIGHT_PARENTHESIS
	{
		$$ = &ast.NamedNumber{
			Name:  string($1),
			Value: &ast.NamedNumber_Reference{
				Reference: string($3),
			},
		}
		Trace("NamedBit: #2", $$)
	}
	;

// X.680 gives ReferencedType three more alternatives, and all three are
// rules - elsewhere. A selection type is written around another type and
// sits with the enclosing types, where a constraint after it binds to the
// type it encloses (see Type). The two drawn from objects are
// InformationFromObjects, under the built-in types, because X.680 lists
// ObjectClassFieldType there and the two are told apart by nothing a
// parser can see.
ReferencedType:
	DefinedType
	{
		$$ = $1
		Trace("ReferencedType: #1", $$)
	}
	;

// X.680 files this under ReferencedType. It sits with the enclosing
// types instead, for the reason they are grouped (see Type): the type it
// selects from has already taken any constraint written after it, so one
// written after "alt < Shape" is the Shape's.
//
// It is the only type that begins with a valuereference, which is why it
// is here at all rather than earlier: putting it within reach of a value
// makes "a < b" two things, since a value range writes "1<..<10" with the
// same "<". A contained subtype therefore takes a DefinedType, where no
// valuereference can appear, and a selection type is written with
// INCLUDES when one is meant. See lib/review.md.
SelectionType:
	TOK_IDENT TOK_LESS_THAN_SIGN Type
	{
		$$ = &ast.Type{
			Kind: &ast.Type_Selection{
				Selection: &ast.SelectionType{
					Name: string($1),
					From: $3,
				},
			},
		}
		Trace("SelectionType: #1", $$)
	}
	;

DefinedType:
	TOK_TYPEREF
	{
		$$ = _Referenced("", string($1))
		Trace("DefinedType: #1", $$)
	}
	| ExternalTypeReference
	{
		$$ = $1
		Trace("DefinedType: #2", $$)
	}
	| TOK_TYPEREF ActualParameterList
	{
		reference := _Referenced("", string($1))
		reference.GetReference().Arguments = $2
		$$ = reference
		Trace("DefinedType: #3", $$)
	}
	| ExternalTypeReference ActualParameterList
	{
		parameterized := $1
		parameterized.GetReference().Arguments = $2
		$$ = parameterized
		Trace("DefinedType: #4", $$)
	}
	;

ActualParameterList:
	TOK_LEFT_CURLY_BRACKET ActualParameterSeries TOK_RIGHT_CURLY_BRACKET
	{
		$$ = $2
		Trace("ActualParameterList: #1", $$)
	}
	;

ActualParameterSeries:
	ActualParameter
	{
		$$ = []*ast.Setting{$1}
		Trace("ActualParameterSeries: #1", $$)
	}
	| ActualParameterSeries TOK_COMMA ActualParameter
	{
		$$ = append($1, $3)
		Trace("ActualParameterSeries: #2", $$)
	}
	;

// X.683 lists six things an actual parameter may be, and the formal
// parameter's governor is what says which - so a parser cannot tell, the
// same way it cannot tell what a braced value holds. Two shapes are kept
// apart here, and only two can be: a type, and anything a value may be.
// A value set and an object set both arrive as the braced value they are
// written as, and the pass that has the governor reads them.
ActualParameter:
	Setting
	{
		$$ = $1
		Trace("ActualParameter: #1", $$)
	}
	| TOK_IDENT ActualParameterList
	{
		// X.683's ParameterizedObject passed as an actual parameter,
		// "combine{{Ops | More}}". As in SubtypeElements, it is written on
		// the tokens rather than reached through Value, because a value in
		// a run reads a name and braces after it as X.680's NamedValue.
		// An actual parameter list separates its parameters with commas
		// and holds no runs.
		$$ = _ValueSetting(_Parameterized("", string($1), $2))
		Trace("ActualParameter: #2", $$)
	}
	;

// X.681's Setting and X.683's ActualParameter are the same list under two
// names: a type, a value, a value set, an object or an object set. Only
// the first two can be told apart by their tokens, and a braced setting
// arrives as the braced value it is written as, for the pass that has the
// governor to read.
Setting:
	Type
	{
		$$ = _TypeSetting($1)
		Trace("Setting: #1", $$)
	}
	| SettingValue
	{
		$$ = _ValueSetting($1)
		Trace("Setting: #2", $$)
	}
	;

ExternalTypeReference:
	TOK_TYPEREF TOK_FULL_STOP TOK_TYPEREF
	{
		$$ = _Referenced(string($1), string($3))
		Trace("ExternalTypeReference: #1", $$)
	}
	;

// A DefinedValue is a valuereference, or one qualified by the module it
// came from. It is kept as the text a module wrote, dot included, because
// nothing here resolves it.
//
// X.683's ParameterizedValue is not an alternative, and this is the one
// place in the grammar that cannot have it: a value may stand in a run, and
// X.680's NamedValue is a component name and the braced value set for it,
// so "v {Args}" inside a braced value reads both ways. It is written on the
// tokens where no run can reach - an element set, an actual parameter, the
// right-hand side of an assignment. See lib/review.md.
DefinedValue:
	TOK_IDENT
	{
		$$ = $1
		Trace("DefinedValue: #1", $$)
	}
	| TOK_TYPEREF TOK_FULL_STOP TOK_IDENT
	{
		$$ = $1 + FULL_STOP + $3
		Trace("DefinedValue: #2", $$)
	}
	;

// ASN.1 value notation is read against the type the value was written
// for. This grammar has no type to read it against - a parser decides on
// tokens, and the type is a name it has not resolved - so where X.680
// gives several alternatives that are the same tokens, they are one rule
// here and the AST records which shape was written rather than what it
// means. Three places this happens:
//
//   - a bare identifier is an IntegerValue's named number, an
//     EnumeratedValue, or a ReferencedValue naming a value defined
//     elsewhere. One rule, through DefinedValue.
//   - a bstring or an hstring is a BitStringValue or an OctetStringValue.
//   - a cstring is a CharacterStringValue, an IRIValue, a
//     RelativeIRIValue or a TimeValue.
//
// Writing X.680's alternatives out instead would be several ways to
// reduce one token, which is a reduce/reduce conflict and a choice yacc
// would then make by rule order - silently, and wrongly as often as not.
//
// The braced values - SequenceValue, SetValue, the OF forms and the
// identifier-list form of BitStringValue - are not here. They collide
// with each other and with ObjectIdentifierValue on the opening brace,
// and they arrive with the constructed types that give them meaning.
// NULL is the one word that is both a type and a value. Everywhere but
// one that costs nothing, because only a value or only a type can stand
// there. The exception is an actual parameter, which X.683 lets be
// either, so the value notation is split here: ActualParameter takes
// NonNullValue and reads a bare NULL as the NULL type instead, which is
// the reading modules mean. See lib/review.md.
Value:
	NonNullValue
	{
		$$ = $1
		Trace("Value: #1", $$)
	}
	| TOK_NULL
	{
		$$ = _Special(NULL)
		Trace("Value: #2", $$)
	}
	;

NonNullValue:
	SettingValue
	{
		$$ = $1
		Trace("NonNullValue: #1", $$)
	}
	| InformationFromObjects
	{
		$$ = &ast.Value{
			Kind: &ast.Value_FromObject{
				FromObject: $1.GetField(),
			},
		}
		Trace("NonNullValue: #2", $$)
	}
	;

// Everything a value may be except a field taken from an object. The two
// are held apart because of the one place a type and a value stand in the
// same position: a setting, which X.681 says is either. "obj.&field" is
// both - which of the five forms X.681 writes for it was meant depends on
// what the field holds - so a setting reads it as the type below and the
// resolver corrects it, and writing it here as well would be two
// reductions of one input. Everywhere else a value stands alone, and there
// it reaches a value through NonNullValue above.
SettingValue:
	TOK_TRUE
	{
		$$ = &ast.Value{Kind: &ast.Value_Boolean{
			Boolean: true,
		}}
		Trace("SettingValue: #1", $$)
	}
	| TOK_FALSE
	{
		$$ = &ast.Value{Kind: &ast.Value_Boolean{
			Boolean: false,
		}}
		Trace("SettingValue: #2", $$)
	}
	| TOK_PLUS_INFINITY
	{
		$$ = _Special(PLUS_INFINITY)
		Trace("SettingValue: #3", $$)
	}
	| TOK_MINUS_INFINITY
	{
		$$ = _Special(MINUS_INFINITY)
		Trace("SettingValue: #4", $$)
	}
	| TOK_NOT_A_NUMBER
	{
		$$ = _Special(NOT_A_NUMBER)
		Trace("SettingValue: #5", $$)
	}
	| NumberValue
	{
		$$ = _Number(string($1))
		Trace("SettingValue: #6", $$)
	}
	| RealNumberValue
	{
		$$ = &ast.Value{Kind: &ast.Value_Real{
			Real: string($1),
		}}
		Trace("SettingValue: #7", $$)
	}
	| StringValue
	{
		$$ = &ast.Value{Kind: &ast.Value_Text{
			Text: string($1),
		}}
		Trace("SettingValue: #8", $$)
	}
	| DefinedValue
	{
		$$ = _Named(string($1))
		Trace("SettingValue: #9", $$)
	}
	| BracedValue
	{
		$$ = $1
		Trace("SettingValue: #10", $$)
	}
	| TOK_BRACES
	{
		$$ = &ast.Value{Kind: &ast.Value_Opaque{
			Opaque: string($1),
		}}
		Trace("SettingValue: #11", $$)
	}
	| DefaultSyntax
	{
		$$ = $1
		Trace("SettingValue: #12", $$)
	}

	| TOK_IDENT TOK_LEFT_PARENTHESIS NumberValue TOK_RIGHT_PARENTHESIS
	{
		$$ = &ast.Value{
			Kind: &ast.Value_NamedNumber{
				NamedNumber: &ast.NamedValue{
					Name:   string($1),
					Number: _Number(string($3)),
				},
			},
		}
		Trace("SettingValue: #13", $$)
	}
	| ConstrainableType TOK_COLON Value
	{
		// X.681's ObjectClassFieldValue: an open type field is set by
		// naming the type before the value, "NULL:NULL". X.680 writes a
		// choice value the same way with an alternative's name in place
		// of the type, and the two are told apart by the case of what
		// precedes the colon, which is a different token.
		//
		// The governor is a ConstrainableType rather than a Type, which
		// leaves out the forms written around another type. One of them
		// has to go: a selection type opens with a valuereference, so
		// "x" before a colon would be a type as readily as the value it
		// already is, and a governor is never written that way.
		$$ = &ast.Value{
			Kind: &ast.Value_Open{
				Open: &ast.OpenValue{
					Type:  $1,
					Value: $3,
				},
			},
		}
		Trace("SettingValue: #14", $$)
	}
	| TOK_IDENT TOK_COLON Value
	{
		$$ = &ast.Value{
			Kind: &ast.Value_Choice{
				Choice: &ast.ChoiceValue{
					Name:  string($1),
					Value: $3,
				},
			},
		}
		Trace("SettingValue: #15", $$)
	}
	;

// Every value X.680 writes between braces is this one rule. It has to be:
// the braces hold an object identifier's arcs, a SEQUENCE's or SET's
// named components, a SEQUENCE OF's or SET OF's values and a BIT STRING's
// named bits, and which of those a module meant is decided by the type
// the value was written for, which a parser has not resolved. The same
// tokens really are several things -
//
//	{ a, b }        a BIT STRING's two bits, or a SEQUENCE OF's two values
//	{ a 1 }         a SEQUENCE's one named component, or two OID arcs
//	{ }             an empty value of any of them
//
// - so writing X.680's alternatives out would be several reductions of
// one input, settled by rule order.
//
// What is kept is the shape: where the commas were, and how many values
// stand between each pair of them. An object identifier's arcs have no
// commas at all and so are one entry of many values; a SEQUENCE's
// components are one entry each, of two values. Nothing is lost, and the
// pass that has the type reads the value off the entries. See
// lib/review.md.
//
// The header's own object identifier keeps its own rule (see
// ObjectIdentifierValue above), because after a modulereference no other
// braced thing can appear and there is nothing to be confused with.
BracedValue:
	TOK_LEFT_CURLY_BRACKET TOK_RIGHT_CURLY_BRACKET
	{
		$$ = _Braced(nil)
		Trace("BracedValue: #1", $$)
	}
	| TOK_LEFT_CURLY_BRACKET ElementValueList TOK_RIGHT_CURLY_BRACKET
	{
		$$ = _Braced($2)
		Trace("BracedValue: #2", $$)
	}
	;

ElementValueList:
	ElementValue
	{
		$$ = []*ast.Element{$1}
		Trace("ElementValueList: #1", $$)
	}
	| ElementValueList TOK_COMMA ElementValue
	{
		$$ = append($1, $3)
		Trace("ElementValueList: #2", $$)
	}
	;

// One entry is a run of values written side by side. Nothing that ends an
// entry - a comma or the closing brace - can begin a value, so the run
// takes another value whenever one follows and stops when one does not.
//
// X.681 writes its objects between these same braces, and their entries
// are settings rather than values - a type, a field reference, or one of
// the class's own words. They are not here, and adding them needs more
// than another alternative: a run that admits both a braced entry after
// another entry and a type that takes a braced suffix is ambiguous, and
// yacc's default resolves it the wrong way round. See lib/review.md.
ElementValue:
	ValueRun
	{
		$$ = _Element($1)
		Trace("ElementValue: #1", $$)
	}
	;

ValueRun:
	Value
	{
		$$ = []*ast.Value{$1}
		Trace("ValueRun: #1", $$)
	}
	| ValueRun Value
	{
		$$ = append($1, $2)
		Trace("ValueRun: #2", $$)
	}
	;

// The lexer fills both union fields for a number: the parsed value, which
// the object identifier arcs and the named numbers want, and the lexeme.
// A value takes the lexeme, through goyacc's $<field>N, because an ASN.1
// INTEGER has no bound and the parsed value is a float64 - reading a
// thirty-digit integer through one would round it and nothing downstream
// could tell.
NumberValue:
	TOK_NUM
	{
		$$ = $<TypeString>1
		Trace("NumberValue: #1", $$)
	}
	| TOK_HYPHEN_MINUS TOK_NUM
	{
		$$ = HYPHEN_MINUS + $<TypeString>2
		Trace("NumberValue: #2", $$)
	}
	;

RealNumberValue:
	TOK_REALNUM
	{
		$$ = $<TypeString>1
		Trace("RealNumberValue: #1", $$)
	}
	| TOK_HYPHEN_MINUS TOK_REALNUM
	{
		$$ = HYPHEN_MINUS + $<TypeString>2
		Trace("RealNumberValue: #2", $$)
	}
	;

StringValue:
	TOK_BSTR
	{
		$$ = $1
		Trace("StringValue: #1", $$)
	}
	| TOK_HSTR
	{
		$$ = $1
		Trace("StringValue: #2", $$)
	}
	| TOK_CSTR
	{
		$$ = $1
		Trace("StringValue: #3", $$)
	}
	;

// SEQUENCE opens either a component list or an OF, and SET the same, so
// the keyword is shifted and the brace or the OF after it says which was
// meant. X.680 writes the two as separate productions and so are these.
SequenceType:
	TOK_SEQUENCE TOK_LEFT_CURLY_BRACKET TOK_RIGHT_CURLY_BRACKET
	{
		$$ = _Builtin(SEQUENCE)
		Trace("SequenceType: #1", $$)
	}
	| TOK_SEQUENCE TOK_LEFT_CURLY_BRACKET ComponentTypeLists TOK_RIGHT_CURLY_BRACKET
	{
		$$ = _Constructed(SEQUENCE, $3)
		Trace("SequenceType: #2", $$)
	}
	;

SetType:
	TOK_SET TOK_LEFT_CURLY_BRACKET TOK_RIGHT_CURLY_BRACKET
	{
		$$ = _Builtin(SET)
		Trace("SetType: #1", $$)
	}
	| TOK_SET TOK_LEFT_CURLY_BRACKET ComponentTypeLists TOK_RIGHT_CURLY_BRACKET
	{
		$$ = _Constructed(SET, $3)
		Trace("SetType: #2", $$)
	}
	;

// X.680 gives the repeated type a name in one of its two forms. No Type
// begins with an identifier, so the identifier alone says which form was
// written and nothing has to be left factored.
SequenceOfType:
	TOK_SEQUENCE TOK_OF Type
	{
		$$ = _Collection(SEQUENCE_OF, $3, "")
		Trace("SequenceOfType: #1", $$)
	}
	| TOK_SEQUENCE TOK_OF NamedType
	{
		$$ = _Collection(SEQUENCE_OF, $3.GetType(), $3.GetName())
		Trace("SequenceOfType: #2", $$)
	}
	;

SetOfType:
	TOK_SET TOK_OF Type
	{
		$$ = _Collection(SET_OF, $3, "")
		Trace("SetOfType: #1", $$)
	}
	| TOK_SET TOK_OF NamedType
	{
		$$ = _Collection(SET_OF, $3.GetType(), $3.GetName())
		Trace("SetOfType: #2", $$)
	}
	;

ChoiceType:
	TOK_CHOICE TOK_LEFT_CURLY_BRACKET AlternativeTypeLists TOK_RIGHT_CURLY_BRACKET
	{
		$$ = _Constructed(CHOICE, $3)
		Trace("ChoiceType: #1", $$)
	}
	;

EnumeratedType:
	TOK_ENUMERATED TOK_LEFT_CURLY_BRACKET Enumerations TOK_RIGHT_CURLY_BRACKET
	{
		$$ = _Constructed(ENUMERATED, $3)
		Trace("EnumeratedType: #1", $$)
	}
	;

// This is where X.680's shape cannot be followed. It writes what sits
// between the braces as a root list, then "...", then the extension
// additions, then optionally a second "..." and a second root list. A
// parser reading one token at a time cannot tell which it is in: after a
// component, a comma is followed either by another component or by the
// marker, and it has already had to reduce by then.
//
// So the list is flat, and the markers are entries in it. Everything
// X.680 writes is still accepted and nothing is thrown away - the marker
// positions are in the list where the module put them - and splitting the
// list into a root and its extensions belongs to the pass that reads it,
// which can also say what a second marker or a marker in the wrong place
// means. A grammar that rejected those would have to be the one X.680
// wrote, which is the thing that cannot be parsed this way. See
// lib/review.md.
ComponentTypeLists:
	ComponentTypeEntry
	{
		$$ = []*ast.Component{$1}
		Trace("ComponentTypeLists: #1", $$)
	}
	| ComponentTypeLists TOK_COMMA ComponentTypeEntry
	{
		$$ = append($1, $3)
		Trace("ComponentTypeLists: #2", $$)
	}
	;

ComponentTypeEntry:
	ComponentType
	{
		$$ = $1
		Trace("ComponentTypeEntry: #1", $$)
	}
	| TOK_ELLIPSIS ExceptionSpec
	{
		$$ = &ast.Component{
			Kind: &ast.Component_Marker{
				Marker: &ast.Marker{
					Exception: $2,
				},
			},
		}
		Trace("ComponentTypeEntry: #2", $$)
	}
	| ExtensionAdditionGroup
	{
		$$ = $1
		Trace("ComponentTypeEntry: #3", $$)
	}
	;

// X.680's own ComponentTypeList, which is what an extension addition
// group holds: plain components, no markers and no nested group.
ComponentTypeList:
	ComponentType
	{
		$$ = []*ast.Component{$1}
		Trace("ComponentTypeList: #1", $$)
	}
	| ComponentTypeList TOK_COMMA ComponentType
	{
		$$ = append($1, $3)
		Trace("ComponentTypeList: #2", $$)
	}
	;

ComponentType:
	NamedType
	{
		$$ = _Component($1)
		Trace("ComponentType: #1", $$)
	}
	| NamedType TOK_OPTIONAL
	{
		component := $1
		component.Optional = true
		$$ = _Component(component)
		Trace("ComponentType: #2", $$)
	}
	| NamedType TOK_DEFAULT Value
	{
		component := $1
		component.Default = $3
		$$ = _Component(component)
		Trace("ComponentType: #3", $$)
	}
	| TOK_COMPONENTS TOK_OF Type
	{
		$$ = &ast.Component{
			Kind: &ast.Component_Of{
				Of: &ast.ComponentsOf{
					Type: $3,
				},
			},
		}
		Trace("ComponentType: #4", $$)
	}
	;

ExtensionAdditionGroup:
	TOK_LEFT_VERSION_BRACKETS VersionNumber ComponentTypeList
	TOK_RIGHT_VERSION_BRACKETS
	{
		$$ = &ast.Component{
			Kind: &ast.Component_Group{
				Group: &ast.Group{
					Version:    int64($2),
					Components: $3,
				},
			},
		}
		Trace("ExtensionAdditionGroup: #1", $$)
	}
	;

// A version number is a number and a colon before the group's contents.
// Nothing a group may begin with is a number, so the empty alternative is
// reduced on anything else and the two never compete.
VersionNumber:
	// Empty
	{
		$$ = 0
		Trace("VersionNumber: #1", $$)
	}
	| TOK_NUM TOK_COLON
	{
		$$ = $1
		Trace("VersionNumber: #2", $$)
	}
	;

// A CHOICE keeps its own list rather than sharing the one above, for one
// difference: X.680 gives its alternatives no OPTIONAL and no DEFAULT,
// and a shared rule would accept both.
AlternativeTypeLists:
	AlternativeTypeEntry
	{
		$$ = []*ast.Component{$1}
		Trace("AlternativeTypeLists: #1", $$)
	}
	| AlternativeTypeLists TOK_COMMA AlternativeTypeEntry
	{
		$$ = append($1, $3)
		Trace("AlternativeTypeLists: #2", $$)
	}
	;

AlternativeTypeEntry:
	NamedType
	{
		$$ = _Component($1)
		Trace("AlternativeTypeEntry: #1", $$)
	}
	| TOK_ELLIPSIS ExceptionSpec
	{
		$$ = &ast.Component{
			Kind: &ast.Component_Marker{
				Marker: &ast.Marker{
					Exception: $2,
				},
			},
		}
		Trace("AlternativeTypeEntry: #2", $$)
	}
	| ExtensionAdditionAlternativesGroup
	{
		$$ = $1
		Trace("AlternativeTypeEntry: #3", $$)
	}
	;

AlternativeTypeList:
	NamedType
	{
		$$ = []*ast.Component{_Component($1)}
		Trace("AlternativeTypeList: #1", $$)
	}
	| AlternativeTypeList TOK_COMMA NamedType
	{
		$$ = append($1, _Component($3))
		Trace("AlternativeTypeList: #2", $$)
	}
	;

ExtensionAdditionAlternativesGroup:
	TOK_LEFT_VERSION_BRACKETS VersionNumber AlternativeTypeList
	TOK_RIGHT_VERSION_BRACKETS
	{
		$$ = &ast.Component{
			Kind: &ast.Component_Group{
				Group: &ast.Group{
					Version:    int64($2),
					Components: $3,
				},
			},
		}
		Trace("ExtensionAdditionAlternativesGroup: #1", $$)
	}
	;

// An ENUMERATED's items are flat for the same reason a SEQUENCE's
// components are, and are kept as components so that a marker means the
// same thing wherever it is written.
Enumerations:
	EnumerationEntry
	{
		$$ = []*ast.Component{$1}
		Trace("Enumerations: #1", $$)
	}
	| Enumerations TOK_COMMA EnumerationEntry
	{
		$$ = append($1, $3)
		Trace("Enumerations: #2", $$)
	}
	;

EnumerationEntry:
	EnumerationItem
	{
		$$ = $1
		Trace("EnumerationEntry: #1", $$)
	}
	| TOK_ELLIPSIS ExceptionSpec
	{
		$$ = &ast.Component{
			Kind: &ast.Component_Marker{
				Marker: &ast.Marker{
					Exception: $2,
				},
			},
		}
		Trace("EnumerationEntry: #2", $$)
	}
	;

// An item is a name, or a name with the number it stands for. The
// parenthesis after the name is what tells them apart, and no item may be
// followed by one, so the bare name is reduced on the comma or the brace
// that ends it.
EnumerationItem:
	TOK_IDENT
	{
		$$ = _Component(&ast.NamedComponent{
			Name: string($1),
		})
		Trace("EnumerationItem: #1", $$)
	}
	| TOK_IDENT TOK_LEFT_PARENTHESIS NumberValue TOK_RIGHT_PARENTHESIS
	{
		$$ = _Component(&ast.NamedComponent{
			Name:   string($1),
			Number: _Number(string($3)),
		})
		Trace("EnumerationItem: #2", $$)
	}
	| TOK_IDENT TOK_LEFT_PARENTHESIS DefinedValue TOK_RIGHT_PARENTHESIS
	{
		$$ = _Component(&ast.NamedComponent{
			Name:   string($1),
			Number: _Named(string($3)),
		})
		Trace("EnumerationItem: #3", $$)
	}
	;

NamedType:
	TOK_IDENT Type
	{
		$$ = &ast.NamedComponent{
			Name: string($1),
			Type: $2,
		}
		Trace("NamedType: #1", $$)
	}
	;

// A type carries its constraints in the order they were written, and the
// rule is left-recursive so that a second constraint lands after the
// first rather than replacing it. Nothing else may follow a type with an
// opening parenthesis, so the decision to take one is a plain shift.
// X.680 lets a SEQUENCE OF or SET OF put its size between the keyword and
// the OF, with or without parentheses around it. After the keyword, the
// brace, the OF, the parenthesis and SIZE each begin a different one of
// the four things it can be, so nothing has to be left factored.
TypeWithConstraint:
	TOK_SEQUENCE CollectionConstraint TOK_OF Type
	{
		collection := _Collection(SEQUENCE_OF, $4, "")
		collection.Constraints = []*ast.Constraint{$2}
		$$ = collection
		Trace("TypeWithConstraint: #1", $$)
	}
	| TOK_SEQUENCE CollectionConstraint TOK_OF NamedType
	{
		collection := _Collection(SEQUENCE_OF, $4.GetType(), $4.GetName())
		collection.Constraints = []*ast.Constraint{$2}
		$$ = collection
		Trace("TypeWithConstraint: #2", $$)
	}
	| TOK_SET CollectionConstraint TOK_OF Type
	{
		collection := _Collection(SET_OF, $4, "")
		collection.Constraints = []*ast.Constraint{$2}
		$$ = collection
		Trace("TypeWithConstraint: #3", $$)
	}
	| TOK_SET CollectionConstraint TOK_OF NamedType
	{
		collection := _Collection(SET_OF, $4.GetType(), $4.GetName())
		collection.Constraints = []*ast.Constraint{$2}
		$$ = collection
		Trace("TypeWithConstraint: #4", $$)
	}
	;

// X.680 has no rule of this name: it writes each of the two spellings out
// against each of SEQUENCE and SET, which is eight productions saying two
// things. The difference between them is only whether the size came
// parenthesised, and a bare SizeConstraint is wrapped here so that both
// reach the AST as the same Constraint.
CollectionConstraint:
	Constraint
	{
		$$ = $1
		Trace("CollectionConstraint: #1", $$)
	}
	| SizeConstraint
	{
		$$ = &ast.Constraint{
			Root: $1,
		}
		Trace("CollectionConstraint: #2", $$)
	}
	;

// X.680 puts the contents constraint under GeneralConstraint, beside
// X.682's table and user-defined constraints, which are here too - the
// table constraints through the pattern section at the foot of this file,
// because a brace at the start of a constraint is already a braced value.
// It is written as a sibling of the element sets, which is where the
// notation puts it, and reaches the AST as the constraint's root so that
// everything a constraint holds has one shape.
//
// The CONTAINING keyword cost something to put here: X.680 23.3 also
// gives it to an OctetStringValue, and "( CONTAINING x )" cannot be both.
// The constraint is what specifications write - an embedded PDU is
// "OCTET STRING (CONTAINING Foo)" in every one of them - and the value
// form is given up for it. See lib/review.md.
Constraint:
	TOK_LEFT_PARENTHESIS ElementSetSpecs ExceptionSpec TOK_RIGHT_PARENTHESIS
	{
		constraint := $2
		constraint.Exception = $3
		$$ = constraint
		Trace("Constraint: #1", $$)
	}
	| TOK_LEFT_PARENTHESIS ElementSetSpecs ComponentRelation ExceptionSpec TOK_RIGHT_PARENTHESIS
	{
		constraint := $2
		constraint.Relation = $3
		constraint.Exception = $4
		$$ = constraint
		Trace("Constraint: #2", $$)
	}
	| TOK_LEFT_PARENTHESIS ContentsConstraint ExceptionSpec TOK_RIGHT_PARENTHESIS
	{
		$$ = &ast.Constraint{
			Root:      $2,
			Exception: $3,
		}
		Trace("Constraint: #3", $$)
	}
	| TOK_LEFT_PARENTHESIS UserDefinedConstraint ExceptionSpec TOK_RIGHT_PARENTHESIS
	{
		$$ = &ast.Constraint{
			Root:      $2,
			Exception: $3,
		}
		Trace("Constraint: #4", $$)
	}
	;

// X.682's CONSTRAINED BY, which hands a constraint to something outside
// ASN.1 and says nothing about what it means. The two reserved words that
// open it are what keep it apart from everything else a parenthesis may
// hold, and the parameters are kept as written.
//
// X.682's other two general constraints, the table constraints, are not
// here: they are written "{ObjectSet}" and "{ObjectSet}{@component}", and
// a brace at the start of a constraint is already a braced value. That is
// the same ambiguity the object notation runs into, and it is waiting on
// the same decision. See lib/review.md.
UserDefinedConstraint:
	TOK_CONSTRAINED TOK_BY TOK_LEFT_CURLY_BRACKET TOK_RIGHT_CURLY_BRACKET
	{
		$$ = &ast.ElementSet{
			Kind: &ast.ElementSet_User{
				User: &ast.UserConstraint{},
			},
		}
		Trace("UserDefinedConstraint: #1", $$)
	}
	| TOK_CONSTRAINED TOK_BY TOK_LEFT_CURLY_BRACKET UserDefinedConstraintParameters TOK_RIGHT_CURLY_BRACKET
	{
		$$ = &ast.ElementSet{
			Kind: &ast.ElementSet_User{
				User: &ast.UserConstraint{
					Settings: $4,
				},
			},
		}
		Trace("UserDefinedConstraint: #2", $$)
	}
	;

UserDefinedConstraintParameters:
	UserDefinedConstraintParameter
	{
		$$ = []*ast.Setting{$1}
		Trace("UserDefinedConstraintParameters: #1", $$)
	}
	| UserDefinedConstraintParameters TOK_COMMA UserDefinedConstraintParameter
	{
		$$ = append($1, $3)
		Trace("UserDefinedConstraintParameters: #2", $$)
	}
	;

// A parameter is a setting, or one whose type or class is named before a
// colon. X.682 writes the second form out four times - a value, an object, a
// value set and an object set, each after a governor and a colon - and all
// four are the open type value NonNullValue already takes, so a setting
// covers both and this is one alternative.
UserDefinedConstraintParameter:
	Setting
	{
		$$ = $1
		Trace("UserDefinedConstraintParameter: #1", $$)
	}
	;

ContentsConstraint:
	TOK_CONTAINING Type
	{
		$$ = &ast.ElementSet{
			Kind: &ast.ElementSet_Contents{
				Contents: &ast.Contents{
					Type: $2,
				},
			},
		}
		Trace("ContentsConstraint: #1", $$)
	}
	| TOK_ENCODED TOK_BY Value
	{
		$$ = &ast.ElementSet{
			Kind: &ast.ElementSet_Contents{
				Contents: &ast.Contents{
					Value: $3,
				},
			},
		}
		Trace("ContentsConstraint: #2", $$)
	}
	| TOK_CONTAINING Type TOK_ENCODED TOK_BY Value
	{
		$$ = &ast.ElementSet{
			Kind: &ast.ElementSet_Contents{
				Contents: &ast.Contents{
					Type:  $2,
					Value: $5,
				},
			},
		}
		Trace("ContentsConstraint: #3", $$)
	}
	;

// A "!" and the value a decoder reports for something it met but does not
// understand. It may follow an extension marker or a constraint, and
// nothing that ends either can begin one, so the empty alternative is
// reduced wherever a "!" was not written.
ExceptionSpec:
	// Empty
	{
		$$ = nil
		Trace("ExceptionSpec: #1", $$)
	}
	| TOK_EXCLAMATION_MARK ExceptionIdentification
	{
		$$ = $2
		Trace("ExceptionSpec: #2", $$)
	}
	;

// X.680's three forms. A signed number and a valuereference are told
// apart by their own tokens; the third begins with a type, and a type
// cannot begin with a valuereference except as a selection type, which
// carries on with "<" where a bare valuereference stops.
ExceptionIdentification:
	NumberValue
	{
		$$ = &ast.Exception{
			Value: _Number(string($1)),
		}
		Trace("ExceptionIdentification: #1", $$)
	}
	| DefinedValue
	{
		$$ = &ast.Exception{
			Value: _Named(string($1)),
		}
		Trace("ExceptionIdentification: #2", $$)
	}
	| Type TOK_COLON Value
	{
		$$ = &ast.Exception{
			Type:  $1,
			Value: $3,
		}
		Trace("ExceptionIdentification: #3", $$)
	}
	;

// The braced type lists had to be flattened because a comma there could
// begin either another entry or the extension marker. Here it cannot: a
// constraint separates its own parts with "|" and "^", so the only comma
// inside the parentheses is the one before the marker, and X.680's own
// shape is kept.
//
// The two alternatives that open with the marker are X.682's, not X.680's:
// an ObjectSetSpec may be nothing but "...", and a set of objects that a
// specification has yet to fill in is written exactly that way -
//
//	E-RABDataForwardingItem-ExtIEs S1AP-PROTOCOL-EXTENSION ::= { ... }
//
// appears in most of the application protocols under testdata/3gpp. An
// object set and a value set are one rule here (see ValueSet), so those
// two alternatives widen what a value set may be, which X.680 does not
// allow and nothing checks yet.
ElementSetSpecs:
	ElementSetSpec
	{
		$$ = &ast.Constraint{
			Root: $1,
		}
		Trace("ElementSetSpecs: #1", $$)
	}
	| TOK_ELLIPSIS
	{
		$$ = &ast.Constraint{
			Extensible: true,
		}
		Trace("ElementSetSpecs: #2", $$)
	}
	| TOK_ELLIPSIS TOK_COMMA ElementSetSpec
	{
		$$ = &ast.Constraint{
			Extensible: true,
			Additional: $3,
		}
		Trace("ElementSetSpecs: #3", $$)
	}
	| ElementSetSpec TOK_COMMA TOK_ELLIPSIS
	{
		$$ = &ast.Constraint{
			Root:       $1,
			Extensible: true,
		}
		Trace("ElementSetSpecs: #4", $$)
	}
	| ElementSetSpec TOK_COMMA TOK_ELLIPSIS TOK_COMMA ElementSetSpec
	{
		$$ = &ast.Constraint{
			Root:       $1,
			Extensible: true,
			Additional: $5,
		}
		Trace("ElementSetSpecs: #5", $$)
	}
	;

ElementSetSpec:
	Unions
	{
		$$ = $1
		Trace("ElementSetSpec: #1", $$)
	}
	| TOK_ALL Exclusions
	{
		$$ = &ast.ElementSet{Kind: &ast.ElementSet_All{
			All: $2,
		}}
		Trace("ElementSetSpec: #2", $$)
	}
	;

// Unions and intersections are left-recursive, which is what makes a
// chain of them nest to the left and an intersection bind tighter than a
// union: "a | b ^ c" is a union of a and an intersection.
Unions:
	Intersections
	{
		$$ = $1
		Trace("Unions: #1", $$)
	}
	| Unions UnionMark Intersections
	{
		$$ = &ast.ElementSet{
			Kind: &ast.ElementSet_Union{
				Union: _Operands($1, $3),
			},
		}
		Trace("Unions: #2", $$)
	}
	;

Intersections:
	IntersectionElements
	{
		$$ = $1
		Trace("Intersections: #1", $$)
	}
	| Intersections IntersectionMark IntersectionElements
	{
		$$ = &ast.ElementSet{
			Kind: &ast.ElementSet_Intersection{
				Intersection: _Operands($1, $3),
			},
		}
		Trace("Intersections: #2", $$)
	}
	;

IntersectionElements:
	Elements
	{
		$$ = $1
		Trace("IntersectionElements: #1", $$)
	}
	| Elements Exclusions
	{
		$$ = &ast.ElementSet{
			Kind: &ast.ElementSet_Except{
				Except: _Operands($1, $2),
			},
		}
		Trace("IntersectionElements: #2", $$)
	}
	;

Exclusions:
	TOK_EXCEPT Elements
	{
		$$ = $2
		Trace("Exclusions: #1", $$)
	}
	;

UnionMark:
	TOK_VERTICAL_LINE
	| TOK_UNION
	;

IntersectionMark:
	TOK_CIRCUMFLEX_ACCENT
	| TOK_INTERSECTION
	;

// X.680's third alternative here is X.681's ObjectSetElements, which is not
// a rule of its own because its four forms are already reachable: an object
// is the braced group the lexer keeps whole, a defined object set is a name,
// one drawn from objects is ObjectClassFieldType under ContainedSubtype, and
// a parameterized one is written on the tokens in SubtypeElements.
Elements:
	SubtypeElements
	{
		$$ = $1
		Trace("Elements: #1", $$)
	}
	| TOK_LEFT_PARENTHESIS ElementSetSpec TOK_RIGHT_PARENTHESIS
	{
		$$ = $2
		Trace("Elements: #2", $$)
	}
	;

// X.680 lists twelve alternatives, and all twelve are here. Three of them
// - DurationRange, TimePointRange and RecurrenceRange - are a ValueRange
// under another name and are covered by that one rule. The general
// constraints of X.682 are not here.
//
// A single value and the lower end of a range are the same Value, and
// nothing decides between them until the token after it: a range
// continues with ".." or "<", and a single value is followed by whatever
// ends an element. The two reductions never compete because those sets do
// not overlap.
SubtypeElements:
	Value
	{
		$$ = _Set($1)
		Trace("SubtypeElements: #1", $$)
	}
	| ValueRange
	{
		$$ = $1
		Trace("SubtypeElements: #2", $$)
	}
	| SizeConstraint
	{
		$$ = $1
		Trace("SubtypeElements: #3", $$)
	}
	| TOK_FROM Constraint
	{
		$$ = &ast.ElementSet{Kind: &ast.ElementSet_Alphabet{
			Alphabet: $2,
		}}
		Trace("SubtypeElements: #4", $$)
	}
	| ContainedSubtype
	{
		$$ = $1
		Trace("SubtypeElements: #5", $$)
	}
	| TOK_IDENT ActualParameterList
	{
		// X.683's ParameterizedObject, "obj{Args}", which an object set is
		// written with. It is taken here and not as a value, because a
		// value may stand in a run - X.680's NamedValue is a name and the
		// value set for it, so "obj {Args}" reads both ways there. An
		// element set has no runs, and nothing else in one begins with a
		// valuereference and a brace.
		$$ = _Set(_Parameterized("", string($1), $2))
		Trace("SubtypeElements: #6", $$)
	}
	| TOK_PATTERN Value
	{
		$$ = &ast.ElementSet{Kind: &ast.ElementSet_Pattern{
			Pattern: $2,
		}}
		Trace("SubtypeElements: #7", $$)
	}
	| TOK_SETTINGS TOK_CSTR
	{
		$$ = &ast.ElementSet{
			Kind: &ast.ElementSet_Settings{
				Settings: string($2),
			},
		}
		Trace("SubtypeElements: #8", $$)
	}
	| InnerTypeConstraints
	{
		$$ = $1
		Trace("SubtypeElements: #9", $$)
	}
	;

// WITH COMPONENT constrains every element of a collection; WITH
// COMPONENTS names the components of a SEQUENCE, SET or CHOICE one at a
// time. The keyword after WITH says which, so the two never compete, and
// neither does the WITH that begins an import's SelectionOption, which
// cannot appear where a constraint may.
InnerTypeConstraints:
	TOK_WITH TOK_COMPONENT Constraint
	{
		$$ = &ast.ElementSet{
			Kind: &ast.ElementSet_Component{
				Component: $3,
			},
		}
		Trace("InnerTypeConstraints: #1", $$)
	}
	| TOK_WITH TOK_COMPONENTS MultipleTypeConstraints
	{
		$$ = $3
		Trace("InnerTypeConstraints: #2", $$)
	}
	;

// X.680's PartialSpecification is the one that opens with "...", saying
// the module is speaking about some of the components and not all of
// them. The "..." is the first thing inside the brace and an identifier
// begins the other form, so one token separates them.
MultipleTypeConstraints:
	TOK_LEFT_CURLY_BRACKET TypeConstraints TOK_RIGHT_CURLY_BRACKET
	{
		$$ = &ast.ElementSet{
			Kind: &ast.ElementSet_Components{
				Components: &ast.WithComponents{
					Named: $2,
				},
			},
		}
		Trace("MultipleTypeConstraints: #1", $$)
	}
	| TOK_LEFT_CURLY_BRACKET TOK_ELLIPSIS TOK_COMMA TypeConstraints TOK_RIGHT_CURLY_BRACKET
	{
		$$ = &ast.ElementSet{
			Kind: &ast.ElementSet_Components{
				Components: &ast.WithComponents{
					Named:   $4,
					Partial: true,
				},
			},
		}
		Trace("MultipleTypeConstraints: #2", $$)
	}
	;

TypeConstraints:
	NamedConstraint
	{
		$$ = []*ast.NamedConstraint{$1}
		Trace("TypeConstraints: #1", $$)
	}
	| TypeConstraints TOK_COMMA NamedConstraint
	{
		$$ = append($1, $3)
		Trace("TypeConstraints: #2", $$)
	}
	;

// X.680 puts the two halves in a ComponentConstraint of their own. They
// are inlined here because both may be left out, and a rule that can
// derive nothing at all only adds a name to read past.
NamedConstraint:
	TOK_IDENT ValueConstraint PresenceConstraint
	{
		$$ = &ast.NamedConstraint{
			Name:       string($1),
			Constraint: $2,
			Presence:   string($3),
		}
		Trace("NamedConstraint: #1", $$)
	}
	;

ValueConstraint:
	// Empty
	{
		$$ = nil
		Trace("ValueConstraint: #1", $$)
	}
	| Constraint
	{
		$$ = $1
		Trace("ValueConstraint: #2", $$)
	}
	;

PresenceConstraint:
	// Empty
	{
		$$ = ""
		Trace("PresenceConstraint: #1", $$)
	}
	| TOK_PRESENT
	{
		$$ = PRESENT
		Trace("PresenceConstraint: #2", $$)
	}
	| TOK_ABSENT
	{
		$$ = ABSENT
		Trace("PresenceConstraint: #3", $$)
	}
	| TOK_OPTIONAL
	{
		$$ = OPTIONAL
		Trace("PresenceConstraint: #4", $$)
	}
	;

// X.680 writes the keyword-less form as a whole Type, which would then be
// a second way to reduce NULL - the one word that is both a type and a
// value - and a second way to reduce a bare type keyword that means
// nothing as a constraint. Only a referenced type is taken without the
// keyword, which is the form every specification writes; INCLUDES covers
// the rest. X.680's TypeConstraint, which is the same production again,
// folds into this one. See lib/review.md.
ContainedSubtype:
	TOK_INCLUDES Type
	{
		$$ = &ast.ElementSet{Kind: &ast.ElementSet_Type{
			Type: $2,
		}}
		Trace("ContainedSubtype: #1", $$)
	}
	| ReferencedType
	{
		$$ = &ast.ElementSet{Kind: &ast.ElementSet_Type{
			Type: $1,
		}}
		Trace("ContainedSubtype: #2", $$)
	}
	| ObjectClassFieldType
	{
		// X.680 lets a contained subtype be any Type, and this rule takes
		// the referenced ones because a Type here would be a value as
		// readily as a type. A field of a class is neither: "Foo.&Bar"
		// opens with a typereference, which no value does, so it can be
		// taken as well - and X.681's object sets are written with it,
		// "My-OperationErrors ERROR ::= {My-Operations.&Errors}".
		$$ = &ast.ElementSet{Kind: &ast.ElementSet_Type{
			Type: $1,
		}}
		Trace("ContainedSubtype: #3", $$)
	}
	;

SizeConstraint:
	TOK_SIZE Constraint
	{
		$$ = &ast.ElementSet{Kind: &ast.ElementSet_Size{
			Size: $2,
		}}
		Trace("SizeConstraint: #1", $$)
	}
	;

ValueRange:
	LowerEndpoint TOK_RANGE_SEPARATOR UpperEndpoint
	{
		$$ = &ast.ElementSet{
			Kind: &ast.ElementSet_Range{
				Range: &ast.Range{
					Lower:     $1.Value,
					Upper:     $3.Value,
					LowerOpen: $1.Open,
					UpperOpen: $3.Open,
				},
			},
		}
		Trace("ValueRange: #1", $$)
	}
	;

// The endpoints carry the value and whether the "<" excluded it, under
// two keys that ValueRange above takes apart again. EXTENSIBLE_KEY is
// reused for the flag because nothing else reads these maps.
LowerEndpoint:
	LowerEndValue
	{
		$$ = &Endpoint{Value: $1, Open: false}
		Trace("LowerEndpoint: #1", $$)
	}
	| LowerEndValue TOK_LESS_THAN_SIGN
	{
		$$ = &Endpoint{Value: $1, Open: true}
		Trace("LowerEndpoint: #2", $$)
	}
	;

UpperEndpoint:
	UpperEndValue
	{
		$$ = &Endpoint{Value: $1, Open: false}
		Trace("UpperEndpoint: #1", $$)
	}
	| TOK_LESS_THAN_SIGN UpperEndValue
	{
		$$ = &Endpoint{Value: $2, Open: true}
		Trace("UpperEndpoint: #2", $$)
	}
	;

// MIN and MAX are reserved words, not values, so they are carried the way
// the other keyword values are: a value whose text is the word itself. A
// range therefore always has both ends and nothing has to read a nil as
// "unbounded".
LowerEndValue:
	Value
	{
		$$ = $1
		Trace("LowerEndValue: #1", $$)
	}
	| TOK_MIN
	{
		$$ = _Special(MIN)
		Trace("LowerEndValue: #2", $$)
	}
	;

UpperEndValue:
	Value
	{
		$$ = $1
		Trace("UpperEndValue: #1", $$)
	}
	| TOK_MAX
	{
		$$ = _Special(MAX)
		Trace("UpperEndValue: #2", $$)
	}
	;


// ---------------------------------------------------------------------
// PATTERNS
//
// Everything above this line is X.680, X.681, X.682 or X.683 written out
// as those specifications write it, with every departure explained at the
// rule that departs.
//
// What follows is different in kind, and is kept apart for that reason.
// These are notations that cannot be reached from the grammar alone -
// they are told apart by a shape the lexer recognizes, not by a token the
// specification put there to tell them apart. Each one names the shape it
// relies on. They are patterns, so they are fallible in a way the rules
// above are not: a module that writes one of these notations differently
// will not be recognized, and will be kept whole as a VALUE_OPAQUE group
// instead. Nothing above depends on anything here.
//
// Put new patterns at the bottom of this section, not above the line.
// ---------------------------------------------------------------------

// X.681's DefaultSyntax: an object written as its class's fields, each
// named. The shape it is recognized by is the field reference the first
// entry opens with, which no value notation has - the lexer leaves such a
// group for this rule rather than keeping it whole (see _LexBraces).
//
// The entries are separated by commas and not written side by side, so
// the setting in one may take a braced suffix of its own without the
// ambiguity that sinks the other object notation: after a setting comes a
// comma or the closing brace, never another setting.
DefaultSyntax:
	TOK_LEFT_CURLY_BRACKET FieldSettingList TOK_RIGHT_CURLY_BRACKET
	{
		$$ = &ast.Value{
			Kind: &ast.Value_Object{
				Object: &ast.Braced{
					Elements: $2,
				},
			},
		}
		Trace("DefaultSyntax: #1", $$)
	}
	;

FieldSettingList:
	FieldSetting
	{
		$$ = []*ast.Element{$1}
		Trace("FieldSettingList: #1", $$)
	}
	| FieldSettingList TOK_COMMA FieldSetting
	{
		$$ = append($1, $3)
		Trace("FieldSettingList: #2", $$)
	}
	;

FieldSetting:
	PrimitiveFieldName Setting
	{
		$$ = &ast.Element{
			Kind: &ast.Element_Setting{
				Setting: &ast.FieldSetting{
					Field: string($1),
					Value: $2,
				},
			},
		}
		Trace("FieldSetting: #1", $$)
	}
	;

// X.682's ComponentRelationConstraint, the "{ObjectSet}{@component}" that
// ties an open type to the field of the object that selects it. The
// object set before it is an ordinary braced value here, and this is the
// part after it.
//
// The shape it is recognized by is the brace followed by an at sign,
// which the lexer returns as a token of its own (see _LexAtBrace). X.682
// writes the two groups as one production; they are split here because a
// brace after a type is otherwise that type's own parameter list, and no
// lookahead separates them.
ComponentRelation:
	TOK_AT_BRACE AtNotationList TOK_RIGHT_CURLY_BRACKET
	{
		$$ = $2
		Trace("ComponentRelation: #1", $$)
	}
	;

AtNotationList:
	AtNotation
	{
		$$ = []*ast.AtNotation{$1}
		Trace("AtNotationList: #1", $$)
	}
	| AtNotationList TOK_COMMA AtNotation
	{
		$$ = append($1, $3)
		Trace("AtNotationList: #2", $$)
	}
	;

// X.682 writes the outer form as "@" and the inner as "@." followed by a
// level of further stops. Level is the count of them, which says how many
// components to go outwards before reading the path.
AtNotation:
	TOK_COMMERCIAL_AT ComponentIdList
	{
		$$ = &ast.AtNotation{
			Path: $2,
		}
		Trace("AtNotation: #1", $$)
	}
	| TOK_COMMERCIAL_AT Level ComponentIdList
	{
		$$ = &ast.AtNotation{
			Level: int64($2),
			Path:  $3,
		}
		Trace("AtNotation: #2", $$)
	}
	;

// How far out from the component being constrained the path starts, counted
// in the full stops written. X.682 writes one stop and then a rule that may
// be empty, so its own Level is one less than this: "@.id" is nought levels
// out and arrives here as 1. Counting the stops is the same language with no
// empty alternative to reduce before the next token is read, and it keeps
// what "@id" means - no stops, so nought - distinct from "@.id".
Level:
	Stops
	{
		$$ = $1
		Trace("Level: #1", $$)
	}
	| Level Stops
	{
		$$ = $1 + $2
		Trace("Level: #2", $$)
	}
	;

// The stops a level is counted in. Two of them and three of them are
// lexical items of their own - a range separator and an extension marker -
// because the lexer takes the longest item that fits and cannot know that
// this one follows an at sign. So "@..id" arrives as one token worth two
// levels and "@...id" as one worth three, and the count is what the rule
// carries rather than the number of tokens.
Stops:
	TOK_FULL_STOP
	{
		$$ = 1
		Trace("Stops: #1", $$)
	}
	| TOK_RANGE_SEPARATOR
	{
		$$ = 2
		Trace("Stops: #2", $$)
	}
	| TOK_ELLIPSIS
	{
		$$ = 3
		Trace("Stops: #3", $$)
	}
	;

ComponentIdList:
	ComponentId
	{
		$$ = []string{string($1)}
		Trace("ComponentIdList: #1", $$)
	}
	| ComponentIdList TOK_FULL_STOP ComponentId
	{
		$$ = append($1, string($3))
		Trace("ComponentIdList: #2", $$)
	}
	;

ComponentId:
	TOK_IDENT
	{
		$$ = $1
		Trace("ComponentId: #1", $$)
	}
	;

%%
