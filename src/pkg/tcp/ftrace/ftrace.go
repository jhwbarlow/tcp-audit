package ftrace

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"strconv"
	"strings"

	"github.com/jhwbarlow/tcp-audit/pkg/tcp"
)

var (
	dashBytes       = []byte{'-'}
	colonSpaceBytes = []byte(": ")
	spaceBytes      = []byte{' '}
	equalsBytes     = []byte{'='}
	underscoreBytes = []byte{'_'}
)

type Eventer struct {
	tracePipe *os.File
	scanner   *bufio.Scanner
}

func New() (*Eventer, error) {
	if err := os.Mkdir("/sys/debug/kernel/tracing/instances/tcp-audit", 0600); err != nil {
		return nil, fmt.Errorf("creating trace instance: %w", err)
	}

	tracePipe, err := os.Open("/sys/debug/kernel/tracing/instances/tcp-audit/trace_pipe")
	if err != nil {
		return nil, fmt.Errorf("opening event trace pipe: %w", err)
	}

	return &Eventer{
		tracePipe: tracePipe,
		scanner:   bufio.NewScanner(tracePipe),
	}, nil
}

func (e *Eventer) Event() (*tcp.Event, error) {
	if !e.scanner.Scan() {
		if err := e.scanner.Err(); err != nil {
			return nil, fmt.Errorf("scanning trace pipe for event: %w", err)
		}

		// No error is still an error - a ring buffer should never return EOF!
		return nil, errors.New("event trace pipe returned unexpected EOF")
	}

	str := e.scanner.Bytes()
	if len(str) == 0 {
		return e.Event()
	}

	event, err := toEvent(str)
	if err != nil {
		return nil, fmt.Errorf("creating event from trace pipe: %w", err)
	}

	return event, nil
}

func (e *Eventer) Close() error {
	var err error
	if closeErr := e.tracePipe.Close(); closeErr != nil {
		err = fmt.Errorf("closing event trace pipe: %w", closeErr)
	}

	if rmInstanceErr := os.Remove("/sys/debug/kernel/tracing/instances/tcp-audit/"); rmInstanceErr != nil {
		err = fmt.Errorf("removing tracing instance: %w", rmInstanceErr)
	}

	return err
}

func toEvent(str []byte) (*tcp.Event, error) {
	command, err := nextField(&str, dashBytes, true)
	if err != nil {
		return nil, fmt.Errorf("parsing command from event: %w", err)
	}
	println("Command:", command)

	pidStr, err := nextField(&str, spaceBytes, true)
	if err != nil {
		return nil, fmt.Errorf("parsing PID from event: %w", err)
	}
	pid, err := strconv.ParseInt(pidStr, 10, 64)
	if err != nil {
		return nil, fmt.Errorf("converting PID to integer: %w", err)
	}
	println("PID:", pid)

	if err := skipField(&str, colonSpaceBytes); err != nil {
		return nil, fmt.Errorf("skipping metadata from event: %w", err)
	}

	if err := skipField(&str, colonSpaceBytes); err != nil {
		return nil, fmt.Errorf("skipping tracepoint from event: %w", err)
	}

	println(string(str))

	// Begin tagged data
	tags, err := getTaggedFields(&str)
	for k, v := range tags {
		println(k, v)
	}
	if err != nil {
		return nil, fmt.Errorf("parsing tagged fields: %w", err)
	}

	family, ok := tags["family"]
	if !ok {
		return nil, errors.New("family not present in event")
	}
	println("Family:", family)

	protocol, ok := tags["protocol"]
	if !ok {
		return nil, errors.New("protocol not present in event")
	}
	println("Protocol:", protocol)

	sPort, ok := tags["sport"]
	if !ok {
		return nil, errors.New("source port not present in event")
	}
	sourcePort, err := strconv.ParseUint(sPort, 10, 16)
	if err != nil {
		return nil, fmt.Errorf("converting source port to integer: %w", err)
	}
	println("Source Port:", sourcePort)

	dPort, ok := tags["dport"]
	if !ok {
		return nil, errors.New("destination port not present in event")
	}
	destPort, err := strconv.ParseUint(dPort, 10, 16)
	if err != nil {
		return nil, fmt.Errorf("converting destination port to integer: %w", err)
	}
	println("Dest Port:", dPort)

	sAddr, ok := tags["saddr"]
	if !ok {
		return nil, errors.New("source address not present in event")
	}
	sourceIP := net.ParseIP(sAddr)
	if sourceIP == nil {
		return nil, errors.New("could not parse source IP address")
	}
	println("Source Addr:", sAddr)

	dAddr, ok := tags["daddr"]
	if !ok {
		return nil, errors.New("destination address not present in event")
	}
	destIP := net.ParseIP(dAddr)
	if destIP == nil {
		return nil, errors.New("could not parse destination IP address")
	}
	println("Dest Addr:", dAddr)

	sAddrV6, ok := tags["saddrv6"]
	if !ok {
		return nil, errors.New("source IPv6 address not present in event")
	}
	println("Source Addr IPv6:", sAddrV6)

	dAddrV6, ok := tags["daddrv6"]
	if !ok {
		return nil, errors.New("destination IPv6 address not present in event")
	}
	println("Dest Addr IPv6:", dAddrV6)

	oldState, ok := tags["oldstate"]
	if !ok {
		return nil, errors.New("old state not present in event")
	}
	canonicalOldState, err := canonicaliseState(oldState)
	if err != nil {
		return nil, fmt.Errorf("canonicalising old state: %w", err)
	}
	println("Old State:", canonicalOldState)

	newState, ok := tags["newstate"]
	if !ok {
		return nil, errors.New("new state not present in event")
	}
	canonicalNewState, err := canonicaliseState(newState)
	if err != nil {
		return nil, fmt.Errorf("canonicalising new state: %w", err)
	}
	println("New State:", canonicalNewState)

	return &tcp.Event{
		CommandOnCPU: command,
		PIDOnCPU:     int(pid),
		SourceIP:     sourceIP,
		DestIP:       destIP,
		SourcePort:   uint16(sourcePort),
		DestPort:     uint16(destPort),
		OldState:     tcp.State(oldState),
		NewState:     tcp.State(newState),
	}, nil
}

func nextField(str *[]byte, sep []byte, expectMoreFields bool) (field string, err error) {
	defer panicToErr(&err) // Catch any unexpected slicing errors without panicking

	idx := bytes.Index(*str, sep)
	if idx == -1 {
		if expectMoreFields {
			return "", io.ErrUnexpectedEOF
		}

		// If the next seperator is not found, assume that the next token is the last in the str
		field = string((*str)[:len(*str)])
		return field, io.EOF
	}

	field = string((*str)[:idx])
	*str = (*str)[idx+1:]

	return field, nil
}

func skipField(str *[]byte, sep []byte) (err error) {
	defer panicToErr(&err) // Catch any unexpected slicing errors without panicking

	idx := bytes.Index(*str, sep)
	*str = (*str)[idx+len(sep):] // Skip over the seperator bytes ready for the next read from str

	return nil
}

func getTaggedFields(str *[]byte) (map[string]string, error) {
	fields := make(map[string]string, 20)
	for {
		nextTag, err := nextField(str, equalsBytes, true) // Expect at least a value after the tag
		if err != nil {
			return nil, fmt.Errorf("parsing next tag: %w", err)
		}

		nextValue, err := nextField(str, spaceBytes, false) // We cannot expect any more fields as this may be the last
		if err != nil && err != io.EOF {
			return nil, fmt.Errorf("parsing next tagged value: %w", err)
		}

		fields[nextTag] = nextValue

		if err == io.EOF { // No more fields in stream
			break
		}
	}

	return fields, nil
}

func panicToErr(err *error) {
	panicData := recover()
	if panicData != nil {
		if panicErr, ok := panicData.(error); ok {
			*err = fmt.Errorf("parsing next field: %w", panicErr)
		} else {
			*err = fmt.Errorf("parsing next field: %v", panicData)
		}
	}
}

func canonicaliseState(state string) (tcp.State, error) {
	state = strings.TrimPrefix(state, "TCP_")
	state = strings.ReplaceAll(state, "_", "-")
	return tcp.StateFromString(state)
}
