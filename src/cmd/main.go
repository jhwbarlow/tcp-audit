package main

import (
	"errors"
	"flag"
	"log"
	"os"
	"os/signal"

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
	done := make(chan struct{})
	cleaner := new(cleaner)

	eventer, err := loadEventer(*eventerFlag)
	if err != nil {
		log.Fatalf("Error: initialising eventer: %v", err)
	}

	sinker, err := loadSinker(*sinkerFlag)
	if err != nil {
		log.Printf("Error: initialising sinker: %v", err)
		cleaner.cleanupEventer(eventer)
		os.Exit(1)
	}

	newRunner(eventer, sinker, cleaner, done, signalChan).run() //TODO: Deal with any errors
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

func installSignalHandler() <-chan os.Signal {
	signalChan := make(chan os.Signal, 1)
	signal.Notify(signalChan, os.Interrupt, unix.SIGTERM)
	return signalChan
}
