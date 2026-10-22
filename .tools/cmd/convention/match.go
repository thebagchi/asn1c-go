package main

import "regexp"

// NO_HISTORY is the diagnostic for a function with no revision history.
const (
	REVISIONS       = "Revisions:"
	NO_HISTORY      = "function has no revision history"
	NOT_INITIAL     = "first revision entry must be initial creation"
	NO_TIME         = "first revision entry must contain the time to the minute"
	BAD_INDENT      = "revision bullet must start with two spaces"
	BAD_LEAD        = "unexported name must start with _ and a capital letter"
	BAD_SNAKE       = "const or package-level var must be CAPITAL_SNAKE"
	BAD_FIELDS      = "struct fields must be contiguous"
	BAD_BODY        = "function body must use more than one line"
	BAD_DEFER       = "deferred closure must use more than one line"
	BAD_GUARD       = "mutex must sit immediately above the data it guards"
	BAD_DECLARE     = "consecutive declarations must use a var block"
	BAD_BANNER      = "banner must be the first line"
	BAD_OPEN        = "a struct literal's first field goes on the line after its brace"
	BAD_SHARED      = "a struct literal holds one field to a line"
	BAD_CLOSE       = "a struct literal's closing brace goes on a line of its own"
	BAD_CALL_OPEN   = "a call's first argument goes on the line after its parenthesis"
	BAD_CALL_SHARED = "a call holds one argument to a line"
	BAD_CALL_CLOSE  = "a call's closing parenthesis goes on a line of its own"
	BAD_SIGN_OPEN   = "a signature's first parameter goes on the line after its parenthesis"
	BAD_SIGN_SHARED = "a signature holds one parameter to a line"
	BAD_SIGN_CLOSE  = "a signature's closing parenthesis goes on a line of its own"
)

// ERR_FORM matches a sentinel error name.
var (
	ERR_FORM    = regexp.MustCompile(`^Err[A-Z][A-Za-z0-9]*$`)
	SNAKE_FORM  = regexp.MustCompile(`^[A-Z][A-Z0-9]*(_[A-Z0-9]+)*$`)
	LEAD_FORM   = regexp.MustCompile(`^_[A-Z][A-Za-z0-9]*$`)
	BANNER_FORM = regexp.MustCompile(`^// Code generated .* DO NOT EDIT\.$`)
	BULLET_FORM = regexp.MustCompile(`^-\s+(.*)$`)
	DASH_FORM   = regexp.MustCompile(`^\s*-\s`)
	INDENT_FORM = regexp.MustCompile(`^   - `)
	TIME_FORM   = regexp.MustCompile(`^[0-9]{4}-[0-9]{2}-[0-9]{2} [0-9]{2}:[0-9]{2}\b`)
)
