package main

import (
	"fmt"
	"log"
	"os"
	"syscall"

	"github.com/jhwbarlow/tcp-audit/pkg/event"
	"github.com/jhwbarlow/tcp-audit/pkg/sink"
)

type runner struct {
	eventer    event.Eventer
	sinker     sink.Sinker
	cleaner    *cleaner
	done       <-chan struct{}
	signalChan <-chan os.Signal
}

func newRunner(eventer event.Eventer,
	sinker sink.Sinker,
	cleaner *cleaner,
	done <-chan struct{},
	signalChan <-chan os.Signal) *runner {
	return &runner{
		eventer:    eventer,
		sinker:     sinker,
		cleaner:    cleaner,
		done:       done,
		signalChan: signalChan,
	}
}

func (r *runner) run() <-chan error {
	eventChan, errChan := r.startGetEvents()

	// Main loop
	errCount := 0
loop:
	for {
		select {
		case signal := <-r.signalChan:
			// Ensure handling a signal takes priority when both a signal is pending
			// and an event is available, hence the nested selects
			r.handleSignal(signal)
		case <-r.done:
			r.cleaner.cleanupAll(r.eventer, r.sinker)
			break loop
		default:
			select {
			case signal := <-r.signalChan:
				// We have to select on the signal channel again, to ensure this select
				// does not block on waiting for an event (or event error) thus stopping
				// the timely handling of a pending signal.
				// We could use 'default' and continue the loop if no event is available,
				// in order to catch a signal, but that is spinning.
				r.handleSignal(signal)
			case <-r.done:
				r.cleaner.cleanupAll(r.eventer, r.sinker)
				break loop
			case event := <-eventChan:
				fmt.Printf("==> TCP state event: %v\n", event)
				if err := r.sinker.Sink(event); err != nil {
					log.Printf("Error: sinking event: %v", err)
				}
				errCount = 0
			case err := <-errChan:
				if err != nil {
					errCount++
					log.Printf("Error: getting event: %v", err)

					if errCount == maxErrors {
						log.Print("Error: too many contiguous event errors")
						r.cleaner.cleanupAll(r.eventer, r.sinker)
						os.Exit(1) // TODO: Should we exit here or pass special error back to main?
					}
				}
			}
		}
	}

	return nil
}

func (r *runner) startGetEvents() (<-chan *event.Event, <-chan error) {
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

func (r *runner) handleSignal(signal os.Signal) {
	exitCode := 0
	if signal, ok := signal.(syscall.Signal); ok {
		exitCode = 127 + int(signal)
	}
	r.cleaner.cleanupAll(r.eventer, r.sinker)
	os.Exit(exitCode) // TODO: Should we exit here or pass special error back to main?
}
