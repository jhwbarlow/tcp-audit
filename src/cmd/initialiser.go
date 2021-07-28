package main

import (
	"fmt"

	"github.com/jhwbarlow/tcp-audit/pkg/event"
	"github.com/jhwbarlow/tcp-audit/pkg/sink"
)

type initialiser struct {
	eventerLoader event.EventerLoader
	sinkerLoader  sink.SinkerLoader
}

func newInitialiser(eventerLoader event.EventerLoader,
	sinkerLoader sink.SinkerLoader) *initialiser {
	return &initialiser{
		eventerLoader: eventerLoader,
		sinkerLoader:  sinkerLoader,
	}
}

func (i *initialiser) initialise() (event.Eventer, sink.Sinker, error) {
	eventer, err := i.eventerLoader.Load()
	if err != nil {
		return nil, nil, fmt.Errorf("initialising eventer: %w", err)
	}

	sinker, err := i.sinkerLoader.Load()
	if err != nil {
		return nil, nil, fmt.Errorf("initialising sinker: %w", err)
	}

	return eventer, sinker, nil
}
