package main

import (
	"log"

	"github.com/jhwbarlow/tcp-audit/pkg/event"
	"github.com/jhwbarlow/tcp-audit/pkg/sink"
)

type cleaner struct{}

func (*cleaner) cleanupEventer(eventer event.Eventer) {
	if eventerCloser, ok := eventer.(event.EventerCloser); ok {
		if closeErr := eventerCloser.Close(); closeErr != nil {
			log.Printf("Error: closing eventer: %v", closeErr)
		}
	}
}

func (*cleaner) cleanupSinker(sinker sink.Sinker) {
	if sinkerCloser, ok := sinker.(sink.SinkerCloser); ok {
		if closeErr := sinkerCloser.Close(); closeErr != nil {
			log.Printf("Error: closing sinker: %v", closeErr)
		}
	}
}

func (c *cleaner) cleanupAll(eventer event.Eventer, sinker sink.Sinker) {
	c.cleanupEventer(eventer)
	c.cleanupSinker(sinker)
}
