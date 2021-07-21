package main

import (
	"errors"
	"fmt"
	"log"
	"os"
	"os/signal"
	"sync"
	"syscall"

	"github.com/jhwbarlow/tcp-audit/pkg/event"
	"github.com/jhwbarlow/tcp-audit/pkg/event/ftrace"
	"golang.org/x/sys/unix"
)

var (
	eventerMutex = new(sync.Mutex)
	eventer      event.Eventer
)

const maxErrors = 5

func main() {
	// Don't allow signal handler to attempt to close
	// an eventer which is under construction
	eventerMutex.Lock()
	installSignalHandler()
	var err error
	eventer, err = ftrace.New()
	if err != nil {
		log.Fatalf("Error: initialising eventer: %v", err)
	}
	eventerMutex.Unlock()

	errorCount := 0
	for {
		event, err := eventer.Event()
		if err != nil {
			errorCount++
			log.Printf("Error: getting event: %v", err)

			if errorCount == maxErrors {
				handleFatalError(errors.New("too many contiguous event errors"))
			}

			continue
		}

		fmt.Printf("==> TCP state event: %v\n", event)
		errorCount = 0
	}
}

func installSignalHandler() {
	signalChan := make(chan os.Signal, 1)
	signal.Notify(signalChan, os.Interrupt, unix.SIGTERM)

	go func(signalChan <-chan os.Signal) {
		signal := <-signalChan
		exitCode := 0
		if signal, ok := signal.(syscall.Signal); ok {
			exitCode = 127 + int(signal)
		}

		cleanupAndExit(exitCode)
	}(signalChan)
}

func handleFatalError(err error) {
	log.Printf("Error: %v", err)
	cleanupAndExit(1)
}

func cleanupAndExit(exitCode int) {
	if eventerCloser, ok := eventer.(event.EventerCloser); ok {
		// Don't allow signal handler to attempt to close
		// an eventer which is already being closed
		// Note this lock will only be "released" on exit
		eventerMutex.Lock()
		if closeErr := eventerCloser.Close(); closeErr != nil {
			log.Printf("Error: closing eventer: %v", closeErr)
		}
	}

	os.Exit(exitCode)
}
