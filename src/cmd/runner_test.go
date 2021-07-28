package main

import (
	"os"
	"testing"

	"github.com/jhwbarlow/tcp-audit/pkg/event"
)

type mockEventer struct{}

func (me *mockEventer) Event() (*event.Event, error) {
	return nil, nil
}

type mockSinker struct{}

func (ms *mockSinker) Sink(*event.Event) error {
	return nil
}

// TestPipeEvent tests that the runner successfully receives
// an event from the Eventer and sends it to the Sinker
func TestPipeEvent(t *testing.T) {
	mockEventer := new(mockEventer)
	mockSinker := new(mockSinker)
	done := make(chan struct{})
	mockSignalChan := make(<-chan os.Signal)
	runner := newRunner(mockEventer, mockSinker, new(cleaner), done, mockSignalChan)

	errChan := make(chan error)
	go func(errChan chan<- error) {
		errChan <- runner.run()
	}(errChan)

	close(done)
	select {
	case err := <-errChan:
		t.Errorf("expected nil error, go %v (of type %T)", err, err)
	default:
	}
}
