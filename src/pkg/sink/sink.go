package sink

import "github.com/jhwbarlow/tcp-audit/pkg/event"

type Sinker interface {
	Sink(*event.Event) error
}

type SinkerCloser interface {
	Sinker
	Close() error
}
