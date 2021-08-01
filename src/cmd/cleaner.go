package main

import (
	"log"

	"github.com/jhwbarlow/tcp-audit/pkg/event"
	"github.com/jhwbarlow/tcp-audit/pkg/sink"
)

type cleaner interface {
	cleanupEventer(eventer event.Eventer)
	cleanupSinker(sinker sink.Sinker)
	cleanupAll(eventer event.Eventer, sinker sink.Sinker)
}

type closingCleaner struct{}

func (*closingCleaner) cleanupEventer(eventer event.Eventer) {
	if eventerCloser, ok := eventer.(event.EventerCloser); ok {
		if closeErr := eventerCloser.Close(); closeErr != nil {
			log.Printf("Error: closing eventer: %v", closeErr)
		}
	}
}

func (*closingCleaner) cleanupSinker(sinker sink.Sinker) {
	if sinkerCloser, ok := sinker.(sink.SinkerCloser); ok {
		if closeErr := sinkerCloser.Close(); closeErr != nil {
			log.Printf("Error: closing sinker: %v", closeErr)
		}
	}
}

func (cc *closingCleaner) cleanupAll(eventer event.Eventer, sinker sink.Sinker) {
	cc.cleanupEventer(eventer)
	cc.cleanupSinker(sinker)
}
