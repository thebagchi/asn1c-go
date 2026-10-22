package mutexorder

import "sync"

type _Store struct {
	values map[string]string
	mu     sync.Mutex
}

type _Guarded struct {
	mu     sync.Mutex
	values map[string]string
}
