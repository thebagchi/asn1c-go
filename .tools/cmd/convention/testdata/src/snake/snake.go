package snake

const camelCase = 1 // want `error: snake:.*fix: spell the name in CAPITAL_SNAKE`

const (
	MAX_RETRIES = 3
)

var ErrClosed = 1

var Analyzer = 1

var notSnake = 1 // want `error: snake:.*fix: spell the name in CAPITAL_SNAKE`

func _F() {
	const alsoCamel = 2 // want `error: snake:.*fix: spell the name in CAPITAL_SNAKE`

	var local = 3
	_ = local
}
