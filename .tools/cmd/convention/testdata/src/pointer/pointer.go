package pointer

import "time"

type _Options struct {
	Root string
}

type _Runner struct {
	Opts *_Options
	Bad  _Options // want `error: pointer:.*fix: change _Options to \*_Options`
	When time.Time
}

type _Wrap struct {
	_Options
}

type _List struct {
	Items []_Options
}

func _Run(opts *_Options, bad _Options) *_Options { // want `error: pointer:.*fix: change _Options to \*_Options`
	return opts
}

func _Value(r _Runner) { // want `error: pointer:.*fix: change _Runner to \*_Runner`
}

func (o _Options) String() string {
	return ""
}

func (o _Options) Error() string {
	return ""
}

func (o _Options) Len() int {
	return 0
}

func (o _Options) Less(i int, j int) bool {
	return false
}

func (o _Options) Swap(i int, j int) {
}

func (o _Options) MarshalJSON() ([]byte, error) {
	return nil, nil
}

func (o _Options) MarshalText() ([]byte, error) {
	return nil, nil
}

func (o _Options) _Get() int { // want `error: pointer:.*fix: change _Options to \*_Options`
	return 0
}

func (r _Runner) String(prefix string) string { // want `error: pointer:.*fix: change _Runner to \*_Runner`
	return prefix
}
