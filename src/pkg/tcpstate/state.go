package tcpstate

import (
	"fmt"
)

// State represents the state of a TCP connection
type State string

// TCP states per RFC 793
const (
	StateListen      State = "LISTEN"
	StateSynSent     State = "SYN-SENT"
	StateSynReceived State = "SYN-RECEIVED"
	StateEstablished State = "ESTABLISHED"
	StateFinWait1    State = "FIN-WAIT-1"
	StateFinWait2    State = "FIN-WAIT-2"
	StateCloseWait   State = "CLOSE-WAIT"
	StateClosing     State = "CLOSING"
	StateLastAck     State = "LAST-ACK"
	StateTimeWait    State = "TIME-WAIT"
	StateClosed      State = "CLOSED"
)

func FromString(state string) (State, error) {
	switch state {
	case string(StateListen):
		return StateListen, nil
	case string(StateSynSent):
		return StateSynSent, nil
	case string(StateSynReceived):
		return StateSynReceived, nil
	case string(StateEstablished):
		return StateEstablished, nil
	case string(StateFinWait1):
		return StateFinWait1, nil
	case string(StateFinWait2):
		return StateFinWait2, nil
	case string(StateCloseWait):
		return StateCloseWait, nil
	case string(StateClosing):
		return StateClosing, nil
	case string(StateLastAck):
		return StateLastAck, nil
	case string(StateTimeWait):
		return StateTimeWait, nil
	case string(StateClosed):
		return StateClosed, nil
	default:
		return State(""), fmt.Errorf("illegal state string: %q", state)
	}
}

func (s State) String() string {
	return string(s)
}
