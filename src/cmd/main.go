package main

import (
	"errors"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/jhwbarlow/tcp-audit/pkg/event"
	"github.com/jhwbarlow/tcp-audit/pkg/pluginload"
	"github.com/jhwbarlow/tcp-audit/pkg/sink"
	"golang.org/x/sys/unix"
)

const (
	eventerFlagStr = "event"
	sinkerFlagStr  = "sink"

	maxErrors = 5
)

var (
	eventerFlag = flag.String(eventerFlagStr, "", "path to eventer plugin")
	sinkerFlag  = flag.String(sinkerFlagStr, "", "path to sinker plugin")
)

func main() {
	flag.Parse()
	if err := checkFlags(); err != nil {
		log.Fatalf("Error: command-line flags: %v", err)
	}

	signalChan := installSignalHandler()

	eventer, err := loadEventer(*eventerFlag)
	if err != nil {
		log.Fatalf("Error: initialising eventer: %v", err)
	}

	sinker, err := loadSinker(*sinkerFlag)
	if err != nil {
		log.Printf("Error: initialising sinker: %v", err)
		cleanupEventer(eventer)
		os.Exit(1)
	}

	eventChan, errChan := startGetEvents(eventer)

	// Main loop
	errCount := 0
	for {
		select {
		case signal := <-signalChan:
			// Ensure handling a signal takes priority when both a signal is pending
			// and an event is available, hence the nested selects
			handleSignal(eventer, sinker, signal)
		default:
			select {
			case signal := <-signalChan:
				// We have to select on the signal channel again, to ensure this select
				// does not block on waiting for an event (or event error) thus stopping
				// the timely handling of a pending signal.
				// We could use 'default' and continue the loop if no event is available,
				// in order to catch a signal, but that is spinning.
				handleSignal(eventer, sinker, signal)
			case event := <-eventChan:
				fmt.Printf("==> TCP state event: %v\n", event)
				if err := sinker.Sink(event); err != nil {
					log.Printf("Error: sinking event: %v", err)
				}
				errCount = 0
			case err := <-errChan:
				if err != nil {
					errCount++
					log.Printf("Error: getting event: %v", err)

					if errCount == maxErrors {
						log.Print("Error: too many contiguous event errors")
						cleanupAll(eventer, sinker)
						os.Exit(1)
					}
				}
			}
		}
	}
}

func checkFlags() error {
	if *sinkerFlag == "" {
		return errors.New(sinkerFlagStr + " not supplied")
	}

	if *eventerFlag == "" {
		return errors.New(eventerFlagStr + " not supplied")
	}

	return nil
}

func installSignalHandler() <-chan os.Signal {
	signalChan := make(chan os.Signal, 1)
	signal.Notify(signalChan, os.Interrupt, unix.SIGTERM)
	return signalChan
}

func startGetEvents(eventer event.Eventer) (<-chan *event.Event, <-chan error) {
	eventChan := make(chan *event.Event)
	errChan := make(chan error)

	go func(chan<- *event.Event, chan<- error) {
		for {
			event, err := eventer.Event()
			if err != nil {
				errChan <- err
				continue
			}

			eventChan <- event
		}
	}(eventChan, errChan)

	return eventChan, errChan
}

func handleSignal(eventer event.Eventer, sinker sink.Sinker, signal os.Signal) {
	exitCode := 0
	if signal, ok := signal.(syscall.Signal); ok {
		exitCode = 127 + int(signal)
	}
	cleanupAll(eventer, sinker)
	os.Exit(exitCode)
}

func loadSinker(path string) (sink.Sinker, error) {
	pluginLoader := pluginload.NewFilesystemSharedObjectPluginLoader(path)
	loader := sink.NewPluginSinkerLoader(pluginLoader)
	return loader.Load()
}

func loadEventer(path string) (event.Eventer, error) {
	pluginLoader := pluginload.NewFilesystemSharedObjectPluginLoader(path)
	loader := event.NewPluginEventerLoader(pluginLoader)
	return loader.Load()
}

func cleanupEventer(eventer event.Eventer) {
	if eventerCloser, ok := eventer.(event.EventerCloser); ok {
		if closeErr := eventerCloser.Close(); closeErr != nil {
			log.Printf("Error: closing eventer: %v", closeErr)
		}
	}
}

func cleanupSinker(sinker sink.Sinker) {
	if sinkerCloser, ok := sinker.(sink.SinkerCloser); ok {
		if closeErr := sinkerCloser.Close(); closeErr != nil {
			log.Printf("Error: closing sinker: %v", closeErr)
		}
	}
}

func cleanupAll(eventer event.Eventer, sinker sink.Sinker) {
	cleanupEventer(eventer)
	cleanupSinker(sinker)
}
