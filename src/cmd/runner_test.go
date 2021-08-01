package main

import (
	"errors"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/jhwbarlow/tcp-audit/pkg/event"
	"github.com/jhwbarlow/tcp-audit/pkg/tcpstate"
)

type mockEventer struct {
	eventChan chan *event.Event
	errChan   chan error
}

func newMockEventer(eventToReturn *event.Event, errToReturn error, noToReturn int) *mockEventer {
	if errToReturn != nil {
		errChan := make(chan error, noToReturn)
		for i := 0; i < noToReturn; i++ {
			errChan <- errToReturn // Buffer up the error so it is read when the runner reads from this eventer
		}

		return &mockEventer{errChan: errChan}
	}

	eventChan := make(chan *event.Event, noToReturn)
	for i := 0; i < noToReturn; i++ {
		eventChan <- eventToReturn // Buffer up the event so it is read when the runner reads from this eventer
	}

	return &mockEventer{eventChan: eventChan}
}

func (me *mockEventer) Event() (*event.Event, error) {
	if me.errChan != nil {
		err := <-me.errChan // Read the next buffered error from chan, block when drained
		return nil, err
	}

	event := <-me.eventChan // Read the next buffered event from chan, block when drained
	return event, nil
}

type mockSinker struct {
	receivedEventChan chan *event.Event
	errChan           chan error
}

func newMockSinker(errToReturn error, noErrToReturn int) *mockSinker {
	if errToReturn != nil {
		errChan := make(chan error, noErrToReturn)
		for i := 0; i < noErrToReturn; i++ {
			errChan <- errToReturn // Buffer up the error so it is read when the runner writes to this sinker
		}

		return &mockSinker{errChan: errChan}
	}

	receivedEventChan := make(chan *event.Event)
	return &mockSinker{receivedEventChan: receivedEventChan}
}

func (ms *mockSinker) Sink(event *event.Event) error {
	if ms.errChan != nil {
		return <-ms.errChan // Read the next buffered error from chan, block when drained
	}

	ms.receivedEventChan <- event
	return nil
}

// TestRunnerEvent tests that the runner successfully receives
// an event from the Eventer and sends it to the Sinker
func TestRunnerEvent(t *testing.T) {
	mockEvent := &event.Event{
		Time:         time.Now(),
		PIDOnCPU:     7337,
		CommandOnCPU: "test",
		SourceIP:     net.ParseIP("1.2.3.4"),
		DestIP:       net.ParseIP("7.3.3.7"),
		SourcePort:   1234,
		DestPort:     7337,
		OldState:     tcpstate.StateClosed,
		NewState:     tcpstate.StateSynReceived,
	}
	mockEventer := newMockEventer(mockEvent, nil, 1)
	mockSinker := newMockSinker(nil, 0)
	done := make(chan struct{})
	runner := newEventPipingRunner(mockEventer, mockSinker, done, maxErrors)
	defer close(done) // Close down the runner

	// The runner runs in an infinite loop so we must run it in its
	// own goroutine so we dont block forever
	errChan := make(chan error)
	go func(errChan chan<- error) {
		errChan <- runner.run()
	}(errChan)

	// Testing the runner is quite difficult as we want to have an eventer
	// which emits just one event. This is then sent to the sinker, which then
	// informs this goroutine that it has done so.
	// In this way we avoid closing the done channel before the runner has
	// processed the event
	event := <-mockSinker.receivedEventChan // The sinker has received the test event
	select {
	case err := <-errChan:
		t.Errorf("expected nil error, got %v (of type %T)", err, err)
	default:
	}

	if !event.Equal(mockEvent) {
		t.Error("expected received event to be equal to sent event")
	}

	t.Logf("received event %q", event)
}

// TestRunnerEventerError tests that the runner successfully stops
// and returns an error when the Eventer returns successive errors
func TestRunnerEventerError(t *testing.T) {
	mockError := errors.New("mock event error")
	mockEventer := newMockEventer(nil, mockError, 3)
	mockSinker := new(mockSinker)
	done := make(chan struct{})
	runner := newEventPipingRunner(mockEventer, mockSinker, done, 3)

	// The runner runs in an infinite loop so we must run it in its
	// own goroutine if we want to be able to cancel it.
	// Testing the runner is quite difficult as we want to have an eventer
	// which emits several errors. These should then be processed by the
	// runner, causing it to exit after the error threshold is reached.
	// The WaitGroup is used to ensure that the runner has exited (and
	// therefore all errors have been processed) before checking the errChan.
	// However, the errChan used to communicate with the main test goroutine
	// must be buffered, so deadlock does not occur between the runner and the
	// test goroutine
	errChan := make(chan error, 1)
	waitGroup := new(sync.WaitGroup)
	waitGroup.Add(1)
	go func(errChan chan<- error) {
		err := runner.run()
		t.Logf("got error %q (of type %T) from runner", err, err)
		errChan <- err
		waitGroup.Done()
	}(errChan)

	waitGroup.Wait()
	select {
	case err := <-errChan:
		t.Logf("got error %q (of type %T)", err, err)
		if !errors.Is(err, mockError) {
			t.Errorf("expected error chain to include %q, but did not", mockError)
		}
	default:
		t.Error("expected error, got nil")
		close(done) // Close down the runner as it will not have closed itself
	}
}

// TestRunnerSinkerError tests that the runner successfully stops
// and returns an error when the Eventer returns successive errors
func TestRunnerSinkerError(t *testing.T) {
	mockEvent := &event.Event{
		Time:         time.Now(),
		PIDOnCPU:     7337,
		CommandOnCPU: "test",
		SourceIP:     net.ParseIP("1.2.3.4"),
		DestIP:       net.ParseIP("7.3.3.7"),
		SourcePort:   1234,
		DestPort:     7337,
		OldState:     tcpstate.StateClosed,
		NewState:     tcpstate.StateSynReceived,
	}
	mockError := errors.New("mock sinker error")
	mockEventer := newMockEventer(mockEvent, nil, 3)
	mockSinker := newMockSinker(mockError, 3)
	done := make(chan struct{})
	runner := newEventPipingRunner(mockEventer, mockSinker, done, 3)

	// The runner runs in an infinite loop so we must run it in its
	// own goroutine if we want to be able to cancel it.
	// Testing the runner is quite difficult as we want to have a sinker
	// which returns several errors. These should then be processed by the
	// runner, causing it to exit after the error threshold is reached.
	// The WaitGroup is used to ensure that the runner has exited (and
	// therefore all errors have been processed) before checking the errChan.
	// However, the errChan used to communicate with the main test goroutine
	// must be buffered, so deadlock does not occur between the runner and the
	// test goroutine
	errChan := make(chan error, 1)
	waitGroup := new(sync.WaitGroup)
	waitGroup.Add(1)
	go func(errChan chan<- error) {
		err := runner.run()
		t.Logf("got error %q (of type %T) from runner", err, err)
		errChan <- err
		waitGroup.Done()
	}(errChan)

	waitGroup.Wait()
	select {
	case err := <-errChan:
		if !errors.Is(err, mockError) {
			t.Errorf("expected error chain to include %q, but did not", mockError)
		}

		t.Logf("got error %q (of type %T)", err, err)
	default:
		t.Error("expected error, got nil")
		close(done) // Close down the runner as it will not have closed itself
	}
}
