package call

func _Zero() {
	_Zero()
}

func _Len(buf []byte) int {
	return len(buf)
}

func _Add(left int, right int) int { // want `error: call:.*first parameter` `error: call:.*one parameter` `error: call:.*closing parenthesis`
	return left + right
}

func _Pair() int {
	return _Sum(1, 2) // want `error: call:.*first argument` `error: call:.*one argument` `error: call:.*closing parenthesis`
}

func _Sum(
	left int,
	right int,
) int {
	return _Sum(
		left,
		right,
	)
}

func _Append(
	buf []byte,
	extra byte,
) []byte {
	return append(buf, extra) // want `error: call:.*first argument` `error: call:.*one argument` `error: call:.*closing parenthesis`
}

func _Conv(
	text string,
) []byte {
	return []byte(text)
}
