package agent

import "sync"

type eventPool struct {
	em     sync.RWMutex
	events map[string]event
}

type event struct {
	tag          string
	frontendPort uint
	// Fill out rest when starting to make labs
}
