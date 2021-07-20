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

	"github.com/google/uuid"
	"github.com/jhwbarlow/tcp-audit/pkg/event"
	"github.com/jhwbarlow/tcp-audit/pkg/tcpstate"
)

const (
	familyInet  = "AF_INET"
	protocolTCP = "IPPROTO_TCP"
)

var errIrrelevantEvent error

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
	instance  string
}

func New() (e *Eventer, err error) {
	// Check whether and where tracefs is mounted
	mountpoint, err := getTraceFSMountpoint()
	if err != nil {
		return nil, fmt.Errorf("obtaining tracefs mountpoint: %w", err)
	}

	// Get tracepoint path
	tracepoint, err := getTracePoint(mountpoint)
	if err != nil {
		return nil, fmt.Errorf("getting tracepoint: %w", err)
	}

	// Create a tracing instance exclusively for this program
	instance, cleanupTracingInstanceFunc, err := createTracingInstance(mountpoint)
	if err != nil {
		return nil, fmt.Errorf("creating tracing instance: %w", err)
	}
	// Only run the cleanup function to undo tracing instance resource creation
	// if this constructor fails at a later point
	defer func() {
		if err != nil {
			cleanupTracingInstanceFunc()
		}
	}()

	// Enable tracing
	if err := enableTracing(instance); err != nil {
		return nil, fmt.Errorf("enabling tracing: %w", err)
	}

	// Enable the tracepoint
	if err := enableTracePoint(instance, tracepoint); err != nil {
		return nil, fmt.Errorf("enabling tracepoint: %w", err)
	}

	// Open the pipe for reading
	tracePipe, cleanupOpenTracePipeFunc, err := openTracePipe(instance, tracepoint)
	if err != nil {
		return nil, fmt.Errorf("opening event trace pipe: %w", err)
	}
	// Only run the cleanup function to undo tracing instance resource creation
	// if this constructor fails at a later point
	defer func() {
		if err != nil {
			cleanupOpenTracePipeFunc()
		}
	}()

	return &Eventer{
		instance:  instance,
		tracePipe: tracePipe,
		scanner:   bufio.NewScanner(tracePipe),
	}, nil
}

func (e *Eventer) Event() (*event.Event, error) {
	var event *event.Event
	var err error
	for {
		if !e.scanner.Scan() {
			if err = e.scanner.Err(); err != nil {
				return nil, fmt.Errorf("scanning trace pipe for event: %w", err)
			}

			// No error is still an error - a ring buffer should never return EOF,
			// instead, reads should block until something is written
			return nil, errors.New("event trace pipe returned unexpected EOF")
		}

		str := e.scanner.Bytes()
		if len(str) == 0 {
			continue
		}

		event, err = toEvent(str)
		if err != nil {
			if err == errIrrelevantEvent {
				continue
			}

			return nil, fmt.Errorf("creating event from trace pipe: %w", err)
		}

		return event, nil
	}
}

func (e *Eventer) Close() error {
	var err error

	if closeErr := closeTracePipe(e.tracePipe); closeErr != nil {
		err = fmt.Errorf("closing event trace pipe: %w", closeErr)
	}

	if cleanupInstanceErr := cleanupInstance(e.instance); cleanupInstanceErr != nil {
		err = fmt.Errorf("cleaning-up trace instance: %w", cleanupInstanceErr)
	}

	return err
}

func getTraceFSMountpoint() (string, error) {
	mounts, err := os.Open("/proc/mounts")
	if err != nil {
		return "", fmt.Errorf("opening mounts: %w", err)
	}

	scanner := bufio.NewScanner(mounts)
	for {
		if !scanner.Scan() {
			if err := scanner.Err(); err != nil {
				return "", fmt.Errorf("scanning mounts for tracefs mountpoint: %w", err)
			}

			// EOF reached but no tracefs mountpoint found
			return "", fmt.Errorf("tracefs not mounted")
		}

		mount := scanner.Bytes()
		device, err := nextField(&mount, spaceBytes, true) // Get device from mount
		if err != nil {
			return "", fmt.Errorf("getting device from mount: %w", err)
		}

		if string(device) == "tracefs" {
			mountpoint, err := nextField(&mount, spaceBytes, true) // Get mountpoint from mount
			if err != nil {
				return "", fmt.Errorf("getting mountpoint from mount: %w", err)
			}

			// tracefs mountpoint successfully located
			return mountpoint, nil
		}
	}
}

func getTracePoint(mountpoint string) (string, error) {
	// Check the tracepoint is available in the running kernel
	_, err := os.Stat(mountpoint + "/events/sock/inet_sock_set_state")
	if err != nil && !os.IsNotExist(err) {
		return "", fmt.Errorf("checking if inet_sock_set_state event present: %w", err)
	}

	if err != nil && os.IsNotExist(err) {
		// Older kernel version has same event but with different fields in /events/tcp/tcp_set_state
		_, err := os.Stat(mountpoint + "/events/tcp/tcp_set_state")
		if err != nil && !os.IsNotExist(err) {
			return "", fmt.Errorf("checking if tcp_set_state event present: %w", err)
		}

		if err != nil && os.IsNotExist(err) {
			return "", errors.New("required tracepoint not available")
		}

		return "tcp/tcp_set_state", nil
	}

	return "sock/inet_sock_set_state", nil
}

func createTracingInstance(mountpoint string) (string, func(), error) {
	uid := uuid.NewString()
	instance := mountpoint + "instances/tcp-audit-" + uid
	if err := os.Mkdir(instance, 0600); err != nil {
		return "", nil, fmt.Errorf("making instance directory: %w", err)
	}

	// A function to undo the creation of the tracing instance
	cleanupFunc := func() {
		cleanupInstance(instance)
	}

	return instance, cleanupFunc, nil
}

func enableTracing(instance string) error {
	tracingOnFile, err := os.Open(instance + "/tracing_on")
	if err != nil {
		return fmt.Errorf("opening tracing_on file: %w", err)
	}
	defer tracingOnFile.Close()
	if _, err := tracingOnFile.WriteString("1"); err != nil {
		return fmt.Errorf("turning tracing on: %w", err)
	}

	return nil
}

func enableTracePoint(instance, tracepoint string) error {
	tracepointFile, err := os.Open(instance + "/events/" + tracepoint + "/enable")
	if err != nil {
		return fmt.Errorf("opening tracepoint enable file: %w", err)
	}
	defer tracepointFile.Close()
	if _, err := tracepointFile.WriteString("1"); err != nil {
		return fmt.Errorf("enabling tracepoint: %w", err)
	}

	return nil
}

func openTracePipe(instance, tracepoint string) (*os.File, func(), error) {
	tracePipe, err := os.Open(instance + "/events/" + tracepoint + "/trace_pipe")
	if err != nil {
		return nil, nil, fmt.Errorf("opening trace_pipe: %w", err)
	}

	// A function to undo the opening of the trace_pipe file
	cleanupFunc := func() {
		closeTracePipe(tracePipe)
	}

	return tracePipe, cleanupFunc, nil
}

func toEvent(str []byte) (*event.Event, error) {
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
	if ok { // Family will not be present if using tcp_set_state
		println("Family:", family)
		if family != familyInet {
			return nil, errIrrelevantEvent
		}
	}

	protocol, ok := tags["protocol"]
	if ok { // Protocol will not be present if using tcp_set_state
		println("Protocol:", protocol)
		if protocol != protocolTCP {
			return nil, errIrrelevantEvent
		}
	}

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

	return &event.Event{
		CommandOnCPU: command,
		PIDOnCPU:     int(pid),
		SourceIP:     sourceIP,
		DestIP:       destIP,
		SourcePort:   uint16(sourcePort),
		DestPort:     uint16(destPort),
		OldState:     tcpstate.State(oldState),
		NewState:     tcpstate.State(newState),
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

func canonicaliseState(state string) (tcpstate.State, error) {
	state = strings.TrimPrefix(state, "TCP_")
	state = strings.ReplaceAll(state, "_", "-")
	return tcpstate.FromString(state)
}

func cleanupInstance(instance string) error {
	if err := os.Remove(instance); err != nil {
		return fmt.Errorf("removing tracing instance: %w", err)
	}

	return nil
}

func closeTracePipe(pipe *os.File) error {
	if err := pipe.Close(); err != nil {
		return fmt.Errorf("closing trace pipe: %w", err)
	}

	return nil
}
