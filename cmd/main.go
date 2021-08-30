package main

import (
	"errors"
	"flag"
	"fmt"
	"log"
	"os"

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
	exiter := new(unixExiter)

	flag.Parse()
	if err := checkFlags(); err != nil {
		log.Printf("Error: command-line flags: %v", err)
		exiter.exitOnError()
	}

	cleaner := new(closingCleaner)
	eventerPluginLoader := pluginload.NewFilesystemSharedObjectPluginLoader(*eventerFlag)
	sinkerPluginLoader := pluginload.NewFilesystemSharedObjectPluginLoader(*sinkerFlag)
	eventer, sinker, err := initPlugins(eventerPluginLoader, sinkerPluginLoader, cleaner)
	if err != nil {
		log.Printf("Error: initialising plugins: %v", err)
		exiter.exitOnError()
	}
	signalHandler := signalhandler.NewOSSignalHandler()
	processor := newPipingEventProcessor(eventer, sinker, maxErrors)

	run(processor, signalHandler, cleaner, exiter)
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

func initPlugins(eventerPluginLoader pluginload.PluginLoader,
	sinkerPluginLoader pluginload.PluginLoader,
	cleaner cleaner) (event.Eventer, sink.Sinker, error) {
	eventer, err := initEventerPlugin(eventerPluginLoader)
	if err != nil {
		return nil, nil, fmt.Errorf("initialising eventer: %w", err)
	}
	cleaner.registerEventer(eventer)

	sinker, err := initSinkerPlugin(sinkerPluginLoader)
	if err != nil {
		cleaner.cleanupEventer()
		return nil, nil, fmt.Errorf("initialising sinker: %w", err)
	}
	cleaner.registerSinker(sinker)

	return eventer, sinker, nil
}

func initEventerPlugin(eventerPluginLoader pluginload.PluginLoader) (event.Eventer, error) {
	eventerLoader := getEventerLoader(eventerPluginLoader)
	eventer, err := loadEventer(eventerLoader)
	if err != nil {
		return nil, fmt.Errorf("loading eventer: %w", err)
	}

	return eventer, nil
}

func initSinkerPlugin(sinkerPluginLoader pluginload.PluginLoader) (sink.Sinker, error) {
	sinkerLoader := getSinkerLoader(sinkerPluginLoader)
	sinker, err := loadSinker(sinkerLoader)
	if err != nil {
		return nil, fmt.Errorf("loading sinker: %w", err)
	}

	return sinker, nil
}

func getSinkerLoader(pluginLoader pluginload.PluginLoader) sink.SinkerLoader {
	return sink.NewPluginSinkerLoader(pluginLoader)
}

func getEventerLoader(pluginLoader pluginload.PluginLoader) event.EventerLoader {
	return event.NewPluginEventerLoader(pluginLoader)
}

func loadEventer(eventerLoader event.EventerLoader) (event.Eventer, error) {
	return eventerLoader.Load()
}

func loadSinker(sinkerLoader sink.SinkerLoader) (sink.Sinker, error) {
	return sinkerLoader.Load()
}

func run(processor eventProcessor, signalHandler signalhandler.SignalHandler, cleaner cleaner, exiter exiter) {
	signalChan, done := signalHandler.Install(os.Interrupt, unix.SIGTERM)

	processor.registerDoneChannel(done)
	if err := processor.run(); err != nil {
		log.Printf("Error: event processor: %v", err)
		cleaner.cleanupAll()
		exiter.exitOnError()
		return // In real life, will not get here, but needed for testing with a mock exiter
	}

	// If we get here, the processor must've stopped due to being asked. This can only happen
	// from a signal, so retrieve it
	cleaner.cleanupAll()
	signal := <-signalChan
	exiter.exitOnSignal(signal)
}
