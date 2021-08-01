package main

import (
	"fmt"
	"log"

	"github.com/jhwbarlow/tcp-audit/pkg/event"
	"github.com/jhwbarlow/tcp-audit/pkg/sink"
)

type runner interface {
	run() error
}

type eventPipingRunner struct {
	eventer   event.Eventer
	sinker    sink.Sinker
	done      <-chan struct{}
	maxErrors int
}

func newEventPipingRunner(eventer event.Eventer,
	sinker sink.Sinker,
	done <-chan struct{},
	maxErrors int) *eventPipingRunner {
	return &eventPipingRunner{
		eventer:   eventer,
		sinker:    sinker,
		done:      done,
		maxErrors: maxErrors,
	}
}

func (r *eventPipingRunner) run() error {
	eventChan, errChan := r.startGetEvents()

	// Main loop
	var lastErr error
	errCount := 0
	wasErr := false
loop:
	for {
		select {
		case <-r.done:
			// Ensure handling a done signal takes priority when both a signal is pending
			// and an event is available, hence the nested selects
			// NOTE: It is non-deterministic which select will process the done signal. This
			// makes it impossible to test both cases. As long as both cases include the same
			// code, however, the test coverage % should be the same every time...
			break loop
		default:
			select {
			case <-r.done:
				// We have to select on the done channel again, to ensure this select
				// does not block on waiting for an event (or event error) thus stopping
				// the timely handling of a pending signal.
				// We could use 'default' and continue the loop if no event is available,
				// in order to catch a signal, but that is spinning.
				break loop
			case event := <-eventChan:
				fmt.Printf("==> TCP state event: %v\n", event)
				if err := r.sinker.Sink(event); err != nil {
					log.Printf("Error: sinking event: %v", err)
					errCount++
					wasErr = true
					lastErr = err
				}
			case err := <-errChan:
				if err != nil {
					log.Printf("Error: getting event: %v", err)
					errCount++
					wasErr = true
					lastErr = err
				}
			}
		}

		if wasErr {
			if errCount == r.maxErrors {
				log.Println("too many contiguous event errors")
				return fmt.Errorf("too many contiguous event errors: last error: %w", lastErr)
			}

			wasErr = false
			continue
		}

		errCount = 0
	}

	// Only get here when the done channel is closed
	return nil
}

func (r *eventPipingRunner) startGetEvents() (<-chan *event.Event, <-chan error) {
	eventChan := make(chan *event.Event)
	errChan := make(chan error)

	go func(chan<- *event.Event, chan<- error) {
		for {
			event, err := r.eventer.Event()
			if err != nil {
				errChan <- err
				continue
			}

			eventChan <- event
		}
	}(eventChan, errChan)

	return eventChan, errChan
}
