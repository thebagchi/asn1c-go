package mutexbetween

import "sync"

type _Between struct {
	values map[string]string
	mu     sync.Mutex
	name   string
}

type _Lead struct {
	mu     sync.Mutex
	values map[string]string
	name   string
}
