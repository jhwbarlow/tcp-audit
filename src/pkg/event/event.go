package event

import (
	"fmt"
	"net"
	"time"

	"github.com/jhwbarlow/tcp-audit/pkg/tcpstate"
)

type Eventer interface {
	Event() (*Event, error)
}

type EventerCloser interface {
	Eventer
	Close() error
}

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
