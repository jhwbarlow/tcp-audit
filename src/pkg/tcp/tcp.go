package tcp

import "net"

type State string

const (
	StateListen      State = "LISTEN"
	StateSynSent     State = "SYN-SENT"
	StateSynReceived State = "SYN-RECEIVED"
	StateEstablished State = "ESTABLISHED"
	StateFinWait1    State = "FIN-WAIT-1"
	StatefinWait2    State = "FIN-WAIT-2"
	StateCloseWait   State = "CLOSE-WAIT"
	StateClosing     State = "CLOSING"
	StateLastAck     State = "LAST-ACK"
	StateTimeWait    State = "TIME-WAIT"
	StateClosed      State = "CLOSED"
)

type Event struct {
	PIDOnCPU             int
	CommandOnCPU         string
	SourceIP, DestIP     net.IP
	SourcePort, DestPort uint16
	OldState, NewState   State
}

type Eventer interface {
	Event() (*Event, error)
}
