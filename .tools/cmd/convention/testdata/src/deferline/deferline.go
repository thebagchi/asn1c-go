package deferline

func _Use() {
	defer func() { _ = 1 }()
}
