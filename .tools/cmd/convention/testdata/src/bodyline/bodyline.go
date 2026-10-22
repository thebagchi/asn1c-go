package bodyline

func _One() { return }

func _Outer() {
	inner := func() { return }
	_ = inner
}
