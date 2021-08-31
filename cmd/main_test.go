package main

import (
	"errors"
	"log"
	"os"
	"plugin"
	"sync"
	"testing"

	"github.com/jhwbarlow/tcp-audit-common/pkg/event"
	"github.com/jhwbarlow/tcp-audit-common/pkg/sink"
	"golang.org/x/sys/unix"
)

type mockProcessor struct {
	registerDoneChannelCalled bool
	done                      <-chan struct{}
	errToReturn               error
}

func newMockProcessor(errToReturn error) *mockProcessor {
	return &mockProcessor{
		errToReturn: errToReturn,
	}
}

func (mp *mockProcessor) run() error {
	if mp.errToReturn != nil {
		return mp.errToReturn
	}

	<-mp.done
	return nil
}

func (mp *mockProcessor) registerDoneChannel(done <-chan struct{}) {
	mp.registerDoneChannelCalled = true
	mp.done = done
}

type mockSignalHandler struct {
	installCalled bool
	signalChanIn  <-chan os.Signal
}

func newMockSignalHandler(signalChanIn <-chan os.Signal) *mockSignalHandler {
	return &mockSignalHandler{
		signalChanIn: signalChanIn,
	}
}

func (msh *mockSignalHandler) Install(signals ...os.Signal) (<-chan os.Signal, <-chan struct{}) {
	msh.installCalled = true

	signalChanOut := make(chan os.Signal, 1)
	done := make(chan struct{})

	go func(done chan<- struct{},
		signalChanIn <-chan os.Signal,
		signalChanOut chan<- os.Signal) {
		signalChanOut <- <-signalChanIn
		close(done)
	}(done, msh.signalChanIn, signalChanOut)

	return signalChanOut, done
}

type mockCleaner struct {
	cleanupAllCalled      bool
	cleanupEventerCalled  bool
	registerEventerCalled bool
	registerSinkerCalled  bool
}

func (mc *mockCleaner) cleanupAll() {
	mc.cleanupAllCalled = true
}

func (mc *mockCleaner) registerEventer(eventer event.Eventer) {
	mc.registerEventerCalled = true
}

func (mc *mockCleaner) cleanupEventer() {
	mc.cleanupEventerCalled = true
}

func (mc *mockCleaner) registerSinker(sinker sink.Sinker) {
	mc.registerSinkerCalled = true
}

func (*mockCleaner) cleanupSinker() {}

type mockExiter struct {
	exitOnErrorCalled  bool
	exitOnSignalCalled bool
	signal             os.Signal
}

func (me *mockExiter) exitOnError() {
	log.Printf("exiting...")
	me.exitOnErrorCalled = true
}

func (me *mockExiter) exitOnSignal(signal os.Signal) {
	me.exitOnSignalCalled = true
	me.signal = signal
}

type mockEventerLoader struct {
	errToReturn error
	loadCalled  bool
}

func (mel *mockEventerLoader) Load() (event.Eventer, error) {
	mel.loadCalled = true

	if mel.errToReturn != nil {
		return nil, mel.errToReturn
	}

	return nil, nil
}

type mockSinkerLoader struct {
	errToReturn error
	loadCalled  bool
}

func (msl *mockSinkerLoader) Load() (sink.Sinker, error) {
	msl.loadCalled = true

	if msl.errToReturn != nil {
		return nil, msl.errToReturn
	}

	return nil, nil
}

type mockPluginLoader struct {
	errorToReturn  error
	symbolToReturn plugin.Symbol
}

func newMockPluginLoader(symbolToReturn plugin.Symbol, errorToReturn error) *mockPluginLoader {
	return &mockPluginLoader{
		symbolToReturn: symbolToReturn,
		errorToReturn:  errorToReturn,
	}
}

func (mpl *mockPluginLoader) Load() (plugin.Symbol, error) {
	if mpl.errorToReturn != nil {
		return nil, mpl.errorToReturn
	}

	return mpl.symbolToReturn, nil
}

func TestRun(t *testing.T) {
	mockProcessor := newMockProcessor(nil)
	signalChan := make(chan os.Signal, 1)
	mockSignalHandler := newMockSignalHandler(signalChan)
	mockCleaner := new(mockCleaner)
	mockExiter := new(mockExiter)

	// Run the processor until a signal is sent (the processor interface
	// implies it runs in an infinite loop until stopped)
	waitGroup := new(sync.WaitGroup)
	waitGroup.Add(1)
	go func() {
		run(mockProcessor, mockSignalHandler, mockCleaner, mockExiter)
		waitGroup.Done()
	}()

	// Cause the mock signal handler to close the done channel, stopping
	// the processor being run in run()
	signalChan <- unix.SIGUSR2

	// Wait for the run function to return so we check it did the correct things
	waitGroup.Wait()

	// Test that run() installed the signal handler
	if !mockSignalHandler.installCalled {
		t.Error("expected SignalHandler to be installed, but was not")
	}

	// Test that run() registered the done channel with the processor
	if !mockProcessor.registerDoneChannelCalled {
		t.Error("expected done channel to be registered, but was not")
	}

	// Test that run() ran the cleaner
	if !mockCleaner.cleanupAllCalled {
		t.Error("expected cleanupAll() to be called, but was not")
	}

	// Test that run() ran the exiter
	if !mockExiter.exitOnSignalCalled {
		t.Error("expected exitOnSignal() to be called, but was not")
	}
}

func TestRunProcessorError(t *testing.T) {
	mockProcessorError := errors.New("mock processor error")
	mockProcessor := newMockProcessor(mockProcessorError)
	signalChan := make(chan os.Signal, 1)
	mockSignalHandler := newMockSignalHandler(signalChan)
	mockCleaner := new(mockCleaner)
	mockExiter := new(mockExiter)

	// Run the processor until a signal is sent (the processor interface
	// implies it runs in an infinite loop until stopped)
	waitGroup := new(sync.WaitGroup)
	waitGroup.Add(1)
	go func() {
		run(mockProcessor, mockSignalHandler, mockCleaner, mockExiter)
		waitGroup.Done()
	}()

	// Wait for the run function to return so we check it did the correct things
	waitGroup.Wait()

	// Test that run() installed the signal handler
	if !mockSignalHandler.installCalled {
		t.Error("expected SignalHandler to be installed, but was not")
	}

	// Test that run() registered the done channel with the processor
	if !mockProcessor.registerDoneChannelCalled {
		t.Error("expected done channel to be registered, but was not")
	}

	// Test that run() ran the cleaner
	if !mockCleaner.cleanupAllCalled {
		t.Error("expected cleanupAll() to be called, but was not")
	}

	// Test that run() ran the exiter
	if !mockExiter.exitOnErrorCalled {
		t.Error("expected exitOnSignal() to be called, but was not")
	}
}

func TestGetEventerLoader(t *testing.T) {
	mockPluginLoader := new(mockPluginLoader)

	eventerLoader := getEventerLoader(mockPluginLoader)

	if _, ok := eventerLoader.(*event.PluginEventerLoader); !ok {
		t.Logf("expected EventerLoader of type PluginEventerLoader, got %T", eventerLoader)
	}
}

func TestGetSinkerLoader(t *testing.T) {
	mockPluginLoader := new(mockPluginLoader)

	sinkerLoader := getSinkerLoader(mockPluginLoader)

	if _, ok := sinkerLoader.(*sink.PluginSinkerLoader); !ok {
		t.Logf("expected SinkerLoader of type PluginSinkerLoader, got %T", sinkerLoader)
	}
}

func TestLoadEventer(t *testing.T) {
	mockEventerLoader := new(mockEventerLoader)

	if _, err := loadEventer(mockEventerLoader); err != nil {
		t.Errorf("expected nil error, got %q (of type %T)", err, err)
	}

	if !mockEventerLoader.loadCalled {
		t.Error("expected EventerLoader Load() to be called, but was not")
	}
}

func TestLoadEventerLoaderError(t *testing.T) {
	mockEventerLoaderError := errors.New("mock eventer loader error")
	mockEventerLoader := &mockEventerLoader{errToReturn: mockEventerLoaderError}

	_, err := loadEventer(mockEventerLoader)
	if err == nil {
		t.Error("expected error, got nil")
	}

	if !errors.Is(err, mockEventerLoaderError) {
		t.Errorf("expected %q error, got %q (of type %T)", mockEventerLoaderError, err, err)
	}

	t.Logf("got error %q (of type %T)", err, err)
}

func TestLoadSinker(t *testing.T) {
	mockSinkerLoader := new(mockSinkerLoader)

	if _, err := loadSinker(mockSinkerLoader); err != nil {
		t.Errorf("expected nil error, got %q (of type %T)", err, err)
	}

	if !mockSinkerLoader.loadCalled {
		t.Error("expected SinkerLoader Load() to be called, but was not")
	}
}

func TestLoadSinkerLoaderError(t *testing.T) {
	mockSinkerLoaderError := errors.New("mock sinker loader error")
	mockSinkerLoader := &mockSinkerLoader{errToReturn: mockSinkerLoaderError}

	_, err := loadSinker(mockSinkerLoader)
	if err == nil {
		t.Error("expected error, got nil")
	}

	if !errors.Is(err, mockSinkerLoaderError) {
		t.Errorf("expected %q error, got %q (of type %T)", mockSinkerLoaderError, err, err)
	}

	t.Logf("got error %q (of type %T)", err, err)
}

func TestNilEventerFlagError(t *testing.T) {
	eventerFlagVar := ""
	eventerFlag = &eventerFlagVar

	// Set the sinkerFlag to some non-empty value to avoid interfering with the test
	sinkerFlagVar := "test sinker flag"
	sinkerFlag = &sinkerFlagVar
	defer func() {
		sinkerFlag = nil
		eventerFlag = nil
	}()

	err := checkFlags()
	if err == nil {
		t.Errorf("expected error, got nil")
	}

	t.Logf("got error %q (of type %T)", err, err)
}

func TestNilSinkerFlagError(t *testing.T) {
	sinkerFlagVar := ""
	sinkerFlag = &sinkerFlagVar

	// Set the eventerFlag to some non-empty value to avoid interfering with the test
	eventerFlagVar := "test eventer flag"
	eventerFlag = &eventerFlagVar
	defer func() {
		sinkerFlag = nil
		eventerFlag = nil
	}()

	err := checkFlags()
	if err == nil {
		t.Errorf("expected error, got nil")
	}

	t.Logf("got error %q (of type %T)", err, err)
}

func TestEventerAndSinkerRegisteredWithCleaner(t *testing.T) {
	mockEventerConstructorSymbol := func() (event.Eventer, error) {
		return nil, nil
	}

	mockSinkerConstructorSymbol := func() (sink.Sinker, error) {
		return nil, nil
	}

	mockPluginLoaderForEventer := newMockPluginLoader(mockEventerConstructorSymbol, nil)
	mockPluginLoaderForSinker := newMockPluginLoader(mockSinkerConstructorSymbol, nil)
	mockCleaner := new(mockCleaner)
	_, _, err := initPlugins(mockPluginLoaderForEventer, mockPluginLoaderForSinker, mockCleaner)
	if err != nil {
		t.Errorf("expected nil error, got %q (of type %T)", err, err)
	}

	if !mockCleaner.registerEventerCalled {
		t.Error("expected Eventer to be registered with cleaner, but was not")
	}

	if !mockCleaner.registerSinkerCalled {
		t.Error("expected Sinker to be registered with cleaner, but was not")
	}
}

func TestInitPluginErrorOnEventerInitFailure(t *testing.T) {
	mockEventerConstructorSymbol := func() {} // Deliberately wrong function signature
	mockSinkerConstructorSymbol := func() (sink.Sinker, error) {
		return nil, nil
	}

	mockPluginLoaderForEventer := newMockPluginLoader(mockEventerConstructorSymbol, nil)
	mockPluginLoaderForSinker := newMockPluginLoader(mockSinkerConstructorSymbol, nil)
	mockCleaner := new(mockCleaner)
	_, _, err := initPlugins(mockPluginLoaderForEventer, mockPluginLoaderForSinker, mockCleaner)
	if err == nil {
		t.Error("expected error, got nil")
	}

	t.Logf("got error %q (of type %T)", err, err)
}

func TestEventerCleanedUpOnSinkerInitFailure(t *testing.T) {
	mockEventerConstructorSymbol := func() (event.Eventer, error) {
		return nil, nil
	}

	mockSinkerConstructorSymbol := func() {} // Deliberately wrong function signature

	mockPluginLoaderForEventer := newMockPluginLoader(mockEventerConstructorSymbol, nil)
	mockPluginLoaderForSinker := newMockPluginLoader(mockSinkerConstructorSymbol, nil)
	mockCleaner := new(mockCleaner)
	_, _, err := initPlugins(mockPluginLoaderForEventer, mockPluginLoaderForSinker, mockCleaner)
	if err == nil {
		t.Error("expected error, got nil")
	}

	t.Logf("got error %q (of type %T)", err, err)

	if !mockCleaner.cleanupEventerCalled {
		t.Error("expected Eventer cleaned up, but was not")
	}
}
