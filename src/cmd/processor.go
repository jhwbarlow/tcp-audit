package main

import (
	"fmt"
	"log"

	"github.com/jhwbarlow/tcp-audit/pkg/event"
	"github.com/jhwbarlow/tcp-audit/pkg/sink"
)

type eventProcessor interface {
	run() error
	registerDoneChannel(<-chan struct{})
}

// PipingEventProcessor "pipes" events directly from the eventer to the sinker.
// No modifications are performed. If the eventer or sinker returns an error,
// the event is dropped.
// If the number of consecutive errors reaches the maxConsecutiveErrors threshold,
// the event processor returns an error.
// By registering a done channel, the caller can cancel the execution of the processor.
// Otherwise, it processes events indefinitely.
type pipingEventProcessor struct {
	eventer              event.Eventer
	sinker               sink.Sinker
	maxConsecutiveErrors int
	done                 <-chan struct{}
}

func newPipingEventProcessor(eventer event.Eventer, sinker sink.Sinker, maxConsecutiveErrors int) *pipingEventProcessor {
	return &pipingEventProcessor{
		eventer:              eventer,
		sinker:               sinker,
		maxConsecutiveErrors: maxConsecutiveErrors,
	}
}

// RegisterDoneChannel registers a done channel. Closing the channel will cause the run method
// to return.
func (ep *pipingEventProcessor) registerDoneChannel(done <-chan struct{}) {
	ep.done = done
}

// Run starts the processor. It will only return if the maxConsecutiveErrors is reached or
// a done channel is registered and subsequently closed.
func (ep *pipingEventProcessor) run() error {
	done := make(chan struct{})
	eventChan, errChan := ep.startGetEvents(done)
	defer close(done)

	// Main loop
	var lastErr error
	errCount := 0
	wasErr := false
loop:
	for {
		select {
		case <-ep.done:
			// Ensure handling a done signal takes priority when both a signal is pending
			// and an event is available, hence the nested selects
			// NOTE: It is non-deterministic which select will process the done signal. This
			// makes it impossible to test both cases. As long as both cases include the same
			// code, however, the test coverage % should be the same every time...
			break loop
		default:
			select {
			case <-ep.done:
				// We have to select on the done channel again, to ensure this select
				// does not block on waiting for an event (or event error) thus stopping
				// the timely handling of a pending signal.
				// We could use 'default' and continue the loop if no event is available,
				// in order to catch a signal, but that is spinning.
				break loop
			case event := <-eventChan:
				fmt.Printf("==> TCP state event: %v\n", event)
				if err := ep.sinker.Sink(event); err != nil {
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
			if errCount == ep.maxConsecutiveErrors {
				log.Println("too many consecutive event errors")
				return fmt.Errorf("too many consecutive event errors: last error: %w", lastErr)
			}

			wasErr = false
			continue
		}

		errCount = 0
	}

	// Only get here when the done channel is closed
	return nil
}

// StartGetEvents calls the eventer in a new goroutine, thus converting a blocking call
// into event and error channels that can be selected upon.
func (ep *pipingEventProcessor) startGetEvents(done <-chan struct{}) (<-chan *event.Event, <-chan error) {
	eventChan := make(chan *event.Event)
	errChan := make(chan error)

	go func(chan<- *event.Event, chan<- error) {
	loop:
		for {
			select {
			case <-done:
				break loop
			default:
			}

			event, err := ep.eventer.Event() // If this is blocked, it will unblock when the eventer is closed

			select {
			case <-done: // Must be checked before potentially blocking on errChan or eventChan that will never be read
				break loop
			default:
			}

			if err != nil {
				errChan <- err
				continue
			}

			eventChan <- event
		}

		close(eventChan)
		close(errChan)
	}(eventChan, errChan)

	return eventChan, errChan
}
