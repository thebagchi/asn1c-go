package lead

func hidden() { // want `error: lead:.*fix: give the name a leading _ and a capital letter`
}

func _hidden() { // want `error: lead:.*fix: give the name a leading _ and a capital letter`
}

func _Shown() {
}

func _Paint[src any]() {
}

func TestShown() {
}

type local struct{} // want `error: lead:.*fix: give the name a leading _ and a capital letter`

type _Local struct{}

type _Store interface {
	hidden() // want `error: lead:.*fix: give the name a leading _ and a capital letter`
	Shown()
}
