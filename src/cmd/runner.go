package main

import (
	"github.com/jhwbarlow/tcp-audit/pkg/event"
	"github.com/jhwbarlow/tcp-audit/pkg/sink"
)

type runner struct {
	eventerLoader event.EventerLoader
	sinkerLoader  sink.SinkerLoader
}

func newRunner(eventerLoader event.EventerLoader, sinkerLoader sink.SinkerLoader) *runner {
	return &runner{
		eventerLoader: eventerLoader,
		sinkerLoader:  sinkerLoader}
}

func (r *runner) run() error {
	
}
