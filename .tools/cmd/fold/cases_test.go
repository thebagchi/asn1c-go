package main

// _Case is one golden case: the source before and the source after fold.
// A case whose want equals its input must produce no change.
type _Case struct {
	name  string
	input string
	want  string
}

// CASES_CALL holds the golden cases for calls.
var (
	CASES_CALL = []_Case{
		{
			name: "call with two arguments",
			input: `package m

func g(a ...int) {}

func Use() {
	g(1, 2)
}
`,
			want: `package m

func g(a ...int) {}

func Use() {
	g(
		1,
		2,
	)
}
`,
		},
		{
			name: "call with three arguments",
			input: `package m

func g(a ...int) {}

func Use() {
	g(1, 2, 3)
}
`,
			want: `package m

func g(a ...int) {}

func Use() {
	g(
		1,
		2,
		3,
	)
}
`,
		},
		{
			name: "nested calls fold inner and outer",
			input: `package m

func g(a ...int) {}

func h(a ...int) int { return 0 }

func Use() {
	g(1, h(2, 3))
}
`,
			want: `package m

func g(a ...int) {}

func h(a ...int) int { return 0 }

func Use() {
	g(
		1,
		h(
			2,
			3,
		),
	)
}
`,
		},
		{
			name: "variadic spread gets a trailing comma",
			input: `package m

func k(
	x int,
	a ...int,
) {
}

func Use(a []int) {
	k(1, a...)
}
`,
			want: `package m

func k(
	x int,
	a ...int,
) {
}

func Use(a []int) {
	k(
		1,
		a...,
	)
}
`,
		},
		{
			name: "function literal argument",
			input: `package m

func run(f ...func()) {}

func Use() {
	run(func() {}, func() {})
}
`,
			want: `package m

func run(f ...func()) {}

func Use() {
	run(
		func() {},
		func() {},
	)
}
`,
		},
		{
			name: "function literal with a body as an argument",
			input: `package m

func run(f ...func()) {}

func Use() {
	run(func() { println(1) }, nil)
}
`,
			want: `package m

func run(f ...func()) {}

func Use() {
	run(
		func() { println(1) },
		nil,
	)
}
`,
		},
		{
			name: "builtin append",
			input: `package m

func Use() []int {
	var s []int

	s = append(s, 1)

	return s
}
`,
			want: `package m

func Use() []int {
	var s []int

	s = append(
		s,
		1,
	)

	return s
}
`,
		},
		{
			name: "builtin make",
			input: `package m

func Use(n int) []int {
	s := make([]int, n)

	return s
}
`,
			want: `package m

func Use(n int) []int {
	s := make(
		[]int,
		n,
	)

	return s
}
`,
		},
		{
			name: "trailing comment after the call stays",
			input: `package m

func g(a ...int) {}

func Use() {
	g(1, 2) // note
}
`,
			want: `package m

func g(a ...int) {}

func Use() {
	g(
		1,
		2,
	) // note
}
`,
		},
		{
			name: "call with one argument stays",
			input: `package m

func g(a ...int) {}

func Use() {
	g(1)
}
`,
			want: `package m

func g(a ...int) {}

func Use() {
	g(1)
}
`,
		},
		{
			name: "call with no argument stays",
			input: `package m

func g(a ...int) {}

func Use() {
	g()
}
`,
			want: `package m

func g(a ...int) {}

func Use() {
	g()
}
`,
		},
		{
			name: "conversion stays",
			input: `package m

func Use(s string) []byte {
	return []byte(s)
}
`,
			want: `package m

func Use(s string) []byte {
	return []byte(s)
}
`,
		},
	}
)

// CASES_PARAMS holds the golden cases for parameter lists.
var (
	CASES_PARAMS = []_Case{
		{
			name: "function declaration with two parameters",
			input: `package m

func Add(a int, b int) int {
	return a + b
}
`,
			want: `package m

func Add(
	a int,
	b int,
) int {
	return a + b
}
`,
		},
		{
			name: "grouped names count one parameter each",
			input: `package m

func Add(a, b int) int {
	return a + b
}
`,
			want: `package m

func Add(
	a,
	b int,
) int {
	return a + b
}
`,
		},
		{
			name: "method with two parameters",
			input: `package m

type T struct{}

func (t *T) Set(a int, b int) {}
`,
			want: `package m

type T struct{}

func (t *T) Set(
	a int,
	b int,
) {
}
`,
		},
		{
			name: "function literal with two parameters",
			input: `package m

var F = func(a int, b int) int { return a + b }
`,
			want: `package m

var F = func(
	a int,
	b int,
) int {
	return a + b
}
`,
		},
		{
			name: "function with one parameter stays",
			input: `package m

func Id(a int) int { return a }
`,
			want: `package m

func Id(a int) int { return a }
`,
		},
		{
			name: "results list stays",
			input: `package m

func Pair() (int, error) { return 0, nil }
`,
			want: `package m

func Pair() (int, error) { return 0, nil }
`,
		},
	}
)

// CASES_LITERAL holds the golden cases for composite literals.
var (
	CASES_LITERAL = []_Case{
		{
			name: "keyed struct literal",
			input: `package m

type P struct {
	x int
	y int
}

var V = P{x: 1, y: 2}
`,
			want: `package m

type P struct {
	x int
	y int
}

var V = P{
	x: 1,
	y: 2,
}
`,
		},
		{
			name: "struct literal with one field",
			input: `package m

type P struct {
	x int
	y int
}

var V = P{x: 1}
`,
			want: `package m

type P struct {
	x int
	y int
}

var V = P{
	x: 1,
}
`,
		},
		{
			name: "unkeyed struct literal",
			input: `package m

type P struct {
	x int
	y int
}

var V = P{1, 2}
`,
			want: `package m

type P struct {
	x int
	y int
}

var V = P{
	1,
	2,
}
`,
		},
		{
			name: "nested struct literal",
			input: `package m

type P struct {
	x int
	y int
}

type Q struct {
	p P
	n int
}

var W = Q{p: P{x: 1, y: 2}, n: 3}
`,
			want: `package m

type P struct {
	x int
	y int
}

type Q struct {
	p P
	n int
}

var W = Q{
	p: P{
		x: 1,
		y: 2,
	},
	n: 3,
}
`,
		},
		{
			name: "address of struct literal",
			input: `package m

type P struct {
	x int
}

var A = &P{x: 1}
`,
			want: `package m

type P struct {
	x int
}

var A = &P{
	x: 1,
}
`,
		},
		{
			name: "elided literal in a slice of pointers",
			input: `package m

type P struct {
	x int
}

var B = []*P{{x: 1}}
`,
			want: `package m

type P struct {
	x int
}

var B = []*P{{
	x: 1,
}}
`,
		},
		{
			name: "elided literal in a slice of values",
			input: `package m

type P struct {
	x int
}

var B = []P{{x: 1}}
`,
			want: `package m

type P struct {
	x int
}

var B = []P{{
	x: 1,
}}
`,
		},
		{
			name: "struct literal as a call argument",
			input: `package m

type P struct {
	x int
}

func g(a ...P) {}

func Use() {
	g(P{x: 1}, P{x: 2})
}
`,
			want: `package m

type P struct {
	x int
}

func g(a ...P) {}

func Use() {
	g(
		P{
			x: 1,
		},
		P{
			x: 2,
		},
	)
}
`,
		},
		{
			name: "empty struct literal stays",
			input: `package m

type P struct {
	x int
}

var E = P{}
`,
			want: `package m

type P struct {
	x int
}

var E = P{}
`,
		},
		{
			name: "slice literal of integers stays",
			input: `package m

var S = []int{1, 2, 3}
`,
			want: `package m

var S = []int{1, 2, 3}
`,
		},
		{
			name: "map literal stays",
			input: `package m

var M = map[string]int{"a": 1}
`,
			want: `package m

var M = map[string]int{"a": 1}
`,
		},
		{
			name: "array literal stays",
			input: `package m

var R = [3]int{1, 2, 3}
`,
			want: `package m

var R = [3]int{1, 2, 3}
`,
		},
	}
)

// CASES_KEEP holds the golden cases for source that must not change.
var (
	CASES_KEEP = []_Case{
		{
			name: "already folded input",
			input: `package m

type P struct {
	x int
	y int
}

func g(a ...int) {}

func Add(
	a int,
	b int,
) int {
	return a + b
}

func Use() {
	g(
		1,
		2,
	)

	_ = P{
		x: 1,
		y: 2,
	}
}
`,
			want: `package m

type P struct {
	x int
	y int
}

func g(a ...int) {}

func Add(
	a int,
	b int,
) int {
	return a + b
}

func Use() {
	g(
		1,
		2,
	)

	_ = P{
		x: 1,
		y: 2,
	}
}
`,
		},
		{
			name: "generated file",
			input: `// Code generated by a tool. DO NOT EDIT.

package m

type P struct {
	x int
}

func g(a ...int) {}

func Add(a int, b int) int {
	return a + b
}

func Use() {
	g(1, 2)

	_ = P{x: 1}
}
`,
			want: `// Code generated by a tool. DO NOT EDIT.

package m

type P struct {
	x int
}

func g(a ...int) {}

func Add(a int, b int) int {
	return a + b
}

func Use() {
	g(1, 2)

	_ = P{x: 1}
}
`,
		},
	}
)
