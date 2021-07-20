package main

import (
	"errors"
	"fmt"
	"log"

	"github.com/jhwbarlow/tcp-audit/pkg/event"
	"github.com/jhwbarlow/tcp-audit/pkg/event/ftrace"
)

const maxErrors = 5

func main() {
	eventer, err := ftrace.New()
	if err != nil {
		log.Fatalf("Error: initialising eventer: %v", err)
	}

	errorCount := 0
	for {
		event, err := eventer.Event()
		if err != nil {
			errorCount++
			log.Printf("Error: getting event: %v", err)

			if errorCount == maxErrors {
				cleanupAndExit(errors.New("too many contiguous event errors"), eventer)
			}
		}

		fmt.Printf("TCP state event: %v\n", event)
		errorCount = 0
	}
}

func cleanupAndExit(err error, eventer event.Eventer) {
	if eventerCloser, ok := eventer.(event.EventerCloser); ok {
		if closeErr := eventerCloser.Close(); closeErr != nil {
			log.Printf("Error: closing eventer: %v", closeErr)
		}
	}

	log.Fatalf("Error: %v", err)
}
