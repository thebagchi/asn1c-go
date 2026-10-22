package declare

func _Run() {
	name := "foo"
	count := 0 // want `error: declare:.*var block`
	_ = name
	_ = count
}

func _Gap() {
	name := "foo"

	count := 0 // want `error: declare:.*var block`
	_ = name
	_ = count
}

func _Three() {
	name := "foo"
	count := 0          // want `error: declare:.*var block`
	items := []string{} // want `error: declare:.*var block`
	_ = name
	_ = count
	_ = items
}

func _One() {
	name := "foo"
	_ = name
}

func _Split() {
	name := "foo"
	_ = name
	count := 0
	_ = name
	_ = count
}

func _Set() {
	name := "foo"
	name = "bar"
	count := 0
	_ = name
	_ = count
}

func _Block() {
	var (
		name  = "foo"
		count = 0
	)
	_ = name
	_ = count
}

func _Case(n int) {
	switch n {
	case 1:
		name := "foo"
		count := 0 // want `error: declare:.*var block`
		_ = name
		_ = count
	}
}

func _Select(ch chan int) {
	select {
	case <-ch:
		name := "foo"
		count := 0 // want `error: declare:.*var block`
		_ = name
		_ = count
	}
}

func _Inner() {
	inner := func() {
		name := "foo"
		count := 0 // want `error: declare:.*var block`
		_ = name
		_ = count
	}
	_ = inner
}
