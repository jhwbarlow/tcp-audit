package ftrace

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"net"
	"os"
	"strconv"

	"github.com/jhwbarlow/tcp-audit/pkg/tcp"
)

var (
	dashBytes       = []byte{'-'}
	colonBytes      = []byte{':'}
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
	command, err := nextField(&str, dashBytes)
	if err != nil {
		return nil, fmt.Errorf("parsing command from event: %w", err)
	}
	println("Command:", command)

	pidStr, err := nextField(&str, spaceBytes)
	if err != nil {
		return nil, fmt.Errorf("parsing PID from event: %w", err)
	}
	pid, err := strconv.ParseInt(pidStr, 10, 64)
	if err != nil {
		return nil, fmt.Errorf("converting PID to integer: %w", err)
	}
	println("PID:", pid)

	if err := skipField(&str, colonBytes); err != nil {
		return nil, fmt.Errorf("skipping metadata from event: %w", err)
	}

	if err := skipField(&str, colonBytes); err != nil {
		return nil, fmt.Errorf("skipping tracepoint from event: %w", err)
	}

	family, err := nextTaggedField(&str)
	if err != nil {
		return nil, fmt.Errorf("parsing family from event: %w", err)
	}
	println("Family:", family)

	protocol, err := nextTaggedField(&str)
	if err != nil {
		return nil, fmt.Errorf("parsing protocol from event: %w", err)
	}
	println("Protocol:", protocol)

	sPort, err := nextTaggedField(&str)
	if err != nil {
		return nil, fmt.Errorf("parsing source port from event: %w", err)
	}
	sourcePort, err := strconv.ParseUint(sPort, 10, 16)
	if err != nil {
		return nil, fmt.Errorf("converting source port to integer: %w", err)
	}
	println("Source Port:", sPort)

	equalsIdx := bytes.Index(str, equalsBytes)
	str = str[equalsIdx+1:]
	spaceIdx := bytes.Index(str, spaceBytes)
	dPort := string(str[:spaceIdx])
	println("Dest Port:", dPort)
	destPort, err := strconv.ParseUint(dPort, 10, 16)
	if err != nil {
		return nil, fmt.Errorf("converting destination port to integer: %w", err)
	}
	str = str[spaceIdx+1:]

	equalsIdx = bytes.Index(str, equalsBytes)
	str = str[equalsIdx+1:]
	spaceIdx = bytes.Index(str, spaceBytes)
	sAddr := string(str[:spaceIdx])
	println("Source Addr:", sAddr)
	sourceIP := net.ParseIP(sAddr)
	if sourceIP == nil {
		return nil, errors.New("could not parse source IP address")
	}
	str = str[spaceIdx+1:]

	equalsIdx = bytes.Index(str, equalsBytes)
	str = str[equalsIdx+1:]
	spaceIdx = bytes.Index(str, spaceBytes)
	dAddr := string(str[:spaceIdx])
	println("Dest Addr:", dAddr)
	destIP := net.ParseIP(dAddr)
	if destIP == nil {
		return nil, errors.New("could not parse destination IP address")
	}
	str = str[spaceIdx+1:]

	equalsIdx = bytes.Index(str, equalsBytes)
	str = str[equalsIdx+1:]
	spaceIdx = bytes.Index(str, spaceBytes)
	sAddrV6 := string(str[:spaceIdx])
	println("Source Addr IPv6:", sAddrV6)
	str = str[spaceIdx+1:]

	equalsIdx = bytes.Index(str, equalsBytes)
	str = str[equalsIdx+1:]
	spaceIdx = bytes.Index(str, spaceBytes)
	dAddrV6 := string(str[:spaceIdx])
	println("Dest Addr IPv6:", dAddrV6)
	str = str[spaceIdx+1:]

	underscoreIdx := bytes.Index(str, underscoreBytes)
	str = str[underscoreIdx+1:]
	spaceIdx = bytes.Index(str, spaceBytes)
	oldState := string(str[:spaceIdx])
	println("Old State:", oldState)
	str = str[spaceIdx+1:]

	underscoreIdx = bytes.Index(str, underscoreBytes)
	str = str[underscoreIdx+1:]
	newState := string(str)
	println("New State:", newState)

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

func nextField(str *[]byte, sep []byte) (field string, err error) {
	defer panicToErr(&err)

	idx := bytes.Index(*str, sep)
	field = string((*str)[:idx])
	*str = (*str)[idx+1:]

	return field, nil
}

func skipField(str *[]byte, sep []byte) (err error) {
	defer panicToErr(&err)

	idx := bytes.Index(*str, sep)
	*str = (*str)[idx+1:]

	return nil
}

func nextTaggedField(str *[]byte) (field string, err error) {
	if err := skipField(str, equalsBytes); err != nil {
		return "", fmt.Errorf("skipping tag: %w", err)
	}

	field, err = nextField(str, spaceBytes)
	if err != nil {
		return "", fmt.Errorf("parsing tagged field: %w", err)
	}

	return field, nil
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
