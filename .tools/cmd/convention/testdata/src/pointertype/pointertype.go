package pointertype

type _Options struct {
	Root string
}

func _Good(opts *_Options) {
	_ = opts
}

func _Known(bad _Options) { // want `error: pointer:.*_Options`
}

func _Closure() {
	inner := func(bad _Options) { // want `error: pointer:.*_Options`
		_ = bad
	}
	_ = inner
}

func _ClosureResult() {
	inner := func() _Options { // want `error: pointer:.*_Options`
		return _Options{}
	}
	_ = inner
}

type _Job interface {
	Run(bad _Options) // want `error: pointer:.*_Options`
}

type _Task func(bad _Options) // want `error: pointer:.*_Options`

var _hook func(bad _Options) // want `error: pointer:.*_Options`

func _Nested(take func(bad _Options)) { // want `error: pointer:.*_Options`
	_ = take
}
