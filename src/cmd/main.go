package main

import (
	"errors"
	"flag"
	"log"
	"os"
	"syscall"

	"github.com/jhwbarlow/tcp-audit/pkg/event"
	"github.com/jhwbarlow/tcp-audit/pkg/pluginload"
	"github.com/jhwbarlow/tcp-audit/pkg/signalhandler"
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

	runner := newEventPipingRunner()
	signalHandler := signalhandler.NewUnixSignalHandler()

	run(*eventerFlag, *sinkerFlag, signalHandler, runner)
}

func run(eventerPath string,
	sinkerPath string,
	signalHandler signalhandler.SignalHandler,
	runner eventPipingRunner) {
	signalChan, done := signalHandler.Install(os.Interrupt, unix.SIGTERM)
	cleaner := new(closingCleaner)

	eventer, err := loadEventer(eventerPath)
	if err != nil {
		log.Fatalf("Error: initialising eventer: %v", err)
	}

	sinker, err := loadSinker(sinkerPath)
	if err != nil {
		log.Printf("Error: initialising sinker: %v", err)
		cleaner.cleanupEventer(eventer)
		os.Exit(1)
	}

	if err := newEventPipingRunner(eventer, sinker, done, maxErrors).run(); err != nil {
		log.Printf("Error: runner: %v", err)
		cleaner.cleanupAll(eventer, sinker)
		os.Exit(1)
	}

	// If we get here, the runner must've stopped due to being asked. This can only happen
	// from a signal, so retrieve it
	cleaner.cleanupAll(eventer, sinker)
	signal := <-signalChan
	handleSignal(signal)
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

func handleSignal(signal os.Signal) {
	exitCode := 0
	if signal, ok := signal.(syscall.Signal); ok {
		exitCode = 127 + int(signal)
	}

	os.Exit(exitCode)
}
