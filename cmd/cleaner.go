package main

import (
	"log"

	"github.com/jhwbarlow/tcp-audit-common/pkg/event"
	"github.com/jhwbarlow/tcp-audit-common/pkg/sink"
)

type cleaner interface {
	registerEventer(eventer event.Eventer)
	cleanupEventer()
	registerSinker(sinker sink.Sinker)
	cleanupSinker()
	cleanupAll()
}

// ClosingCleaner cleans-up the registered eventer and/or sinker by calling their
// close methods, if applicable.
type closingCleaner struct {
	eventer event.Eventer
	sinker  sink.Sinker
}

func (cc *closingCleaner) registerEventer(eventer event.Eventer) {
	cc.eventer = eventer
}

func (cc *closingCleaner) registerSinker(sinker sink.Sinker) {
	cc.sinker = sinker
}

func (cc *closingCleaner) cleanupEventer() {
	if eventerCloser, ok := cc.eventer.(event.EventerCloser); ok {
		if closeErr := eventerCloser.Close(); closeErr != nil {
			log.Printf("Error: closing eventer: %v", closeErr)
		}
	}
}

func (cc *closingCleaner) cleanupSinker() {
	if sinkerCloser, ok := cc.sinker.(sink.SinkerCloser); ok {
		if closeErr := sinkerCloser.Close(); closeErr != nil {
			log.Printf("Error: closing sinker: %v", closeErr)
		}
	}
}

func (cc *closingCleaner) cleanupAll() {
	cc.cleanupEventer()
	cc.cleanupSinker()
}
