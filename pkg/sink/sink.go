package sink

import "github.com/jhwbarlow/tcp-audit/pkg/event"

// Sinker is an interface which describes objects which sink TCP state change events
type Sinker interface {
	Sink(*event.Event) error
}

// SinkerCloser is an interface which describes Sinkers which must be closed when no
// longer needed in order to free resources they have acquired.
type SinkerCloser interface {
	Sinker
	Close() error
}
