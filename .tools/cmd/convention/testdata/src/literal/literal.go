package literal

type _Box struct {
	N int
	M int
}

func _Good() {
	box := _Box{
		N: 1,
	}
	_ = box

	empty := _Box{}
	_ = empty

	items := []*_Box{
		{
			N: 2,
		},
	}
	_ = items

	nums := []int{1, 2}
	_ = nums
}

func _Open() {
	box := _Box{N: 1} // want `error: literal:.*first field` `error: literal:.*closing brace`
	_ = box
}

func _Shared() {
	box := _Box{
		N: 1, M: 2, // want `error: literal:.*one field to a line`
	}
	_ = box
}

func _Close() {
	box := _Box{
		N: 1} // want `error: literal:.*closing brace`
	_ = box
}

func _Elided() {
	items := []*_Box{
		{N: 1}, // want `error: literal:.*first field` `error: literal:.*closing brace`
	}
	_ = items
}

func _Address() {
	box := &_Box{N: 1} // want `error: literal:.*first field` `error: literal:.*closing brace`
	_ = box
}
