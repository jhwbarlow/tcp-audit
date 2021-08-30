package event

import (
	"fmt"
	"net"
	"time"

	"github.com/jhwbarlow/tcp-audit/pkg/tcpstate"
)

// Eventer is an interface which describes objects which emit TCP state change events
type Eventer interface {
	Event() (*Event, error)
}

// EventerCloser is an interface which describes Eventers which must be closed when no
// longer needed in order to free resources they have acquired.
type EventerCloser interface {
	Eventer
	Close() error
}

// Event is a TCP state change event
type Event struct {
	Time                 time.Time
	PIDOnCPU             int
	CommandOnCPU         string
	SourceIP, DestIP     net.IP
	SourcePort, DestPort uint16
	OldState, NewState   tcpstate.State
}

func (e *Event) String() string {
	return fmt.Sprintf("PID (on CPU): %d, Command (on CPU): %s, Source Port: %v:%d, Destination Port: %v:%d, Old State: %v, New State: %v",
		e.PIDOnCPU,
		e.CommandOnCPU,
		e.SourceIP,
		e.SourcePort,
		e.DestIP,
		e.DestPort,
		e.OldState,
		e.NewState)
}

func (e *Event) Equal(event *Event) bool {
	return event.Time == e.Time &&
		event.PIDOnCPU == e.PIDOnCPU &&
		event.CommandOnCPU == e.CommandOnCPU &&
		event.SourceIP.Equal(e.SourceIP) &&
		event.DestIP.Equal(e.DestIP) &&
		event.SourcePort == e.SourcePort &&
		event.DestPort == e.DestPort &&
		event.OldState == e.OldState &&
		event.NewState == e.NewState
}
