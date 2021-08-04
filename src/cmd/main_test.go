package main

import (
	"errors"
	"os"
	"plugin"
	"testing"

	"github.com/jhwbarlow/tcp-audit/pkg/event"
	"github.com/jhwbarlow/tcp-audit/pkg/sink"
	"golang.org/x/sys/unix"
)

type mockProcessor struct {
	registerDoneChannelCalled chan bool
	done                      <-chan struct{}
	errToReturn               error
}

func newMockProcessor(errToReturn error) *mockProcessor {
	registerDoneChannelCalled := make(chan bool)

	return &mockProcessor{
		registerDoneChannelCalled: registerDoneChannelCalled,
		errToReturn:               errToReturn,
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
	mp.registerDoneChannelCalled <- true
	mp.done = done
}

type mockSignalHandler struct {
	installCalled chan bool
	signalChanIn  <-chan os.Signal
}

func newMockSignalHandler(signalChanIn <-chan os.Signal) *mockSignalHandler {
	installCalled := make(chan bool)
	return &mockSignalHandler{
		signalChanIn:  signalChanIn,
		installCalled: installCalled}
}

func (msh *mockSignalHandler) Install(signals ...os.Signal) (<-chan os.Signal, <-chan struct{}) {
	msh.installCalled <- true

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

func newMockCleaner() *mockCleaner {
	cleanupAllCalled := make(chan bool)
	return &mockCleaner{cleanupAllCalled}
}

type mockCleaner struct {
	cleanupAllCalled chan bool
}

func (mc *mockCleaner) cleanupAll() {
	mc.cleanupAllCalled <- true
}

func (*mockCleaner) registerEventer(eventer event.Eventer) {}

func (*mockCleaner) cleanupEventer() {}

func (*mockCleaner) registerSinker(sinker sink.Sinker) {}

func (*mockCleaner) cleanupSinker() {}

type mockExiter struct {
	exitOnErrorCalled  chan bool
	exitOnSignalCalled chan bool
	signal             os.Signal
}

func newMockExiter() *mockExiter {
	exitOnErrorCalled := make(chan bool)
	exitOnSignalCalled := make(chan bool)

	return &mockExiter{
		exitOnErrorCalled:  exitOnErrorCalled,
		exitOnSignalCalled: exitOnSignalCalled,
	}
}

func (me *mockExiter) exitOnError() {
	me.exitOnErrorCalled <- true
}

func (me *mockExiter) exitOnSignal(signal os.Signal) {
	me.exitOnSignalCalled <- true
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

type mockPluginLoader struct{}

func (mpl *mockPluginLoader) Load() (plugin.Symbol, error) {
	return nil, nil
}

func TestRun(t *testing.T) {
	mockProcessor := newMockProcessor(nil)
	signalChan := make(chan os.Signal, 1)
	mockSignalHandler := newMockSignalHandler(signalChan)
	mockCleaner := newMockCleaner()
	mockExiter := newMockExiter()

	// Run the processor until a signal is sent (the processor interface
	// implies it runs in an infinite loop until stopped)
	go run(mockProcessor, mockSignalHandler, mockCleaner, mockExiter)

	// Cause the mock signal handler to close the done channel, stopping
	// the processor being run in run()
	signalChan <- unix.SIGUSR2

	// Test that run() installed the signal handler
	if !<-mockSignalHandler.installCalled {
		t.Error("expected SignalHandler to be installed, but was not")
	}

	// Test that run() registered the done channel with the processor
	if !<-mockProcessor.registerDoneChannelCalled {
		t.Error("expected done channel to be registered, but was not")
	}

	// Test that run() ran the cleaner
	if !<-mockCleaner.cleanupAllCalled {
		t.Error("expected cleanupAll() to be called, but was not")
	}

	// Test that run() ran the exiter
	if !<-mockExiter.exitOnSignalCalled {
		t.Error("expected exitOnSignal() to be called, but was not")
	}
}

func TestRunProcessorError(t *testing.T) {
	mockProcessorError := errors.New("mock processor error")
	mockProcessor := newMockProcessor(mockProcessorError)
	signalChan := make(chan os.Signal, 1)
	mockSignalHandler := newMockSignalHandler(signalChan)
	mockCleaner := newMockCleaner()
	mockExiter := newMockExiter()

	// Run the processor until a signal is sent (the processor interface
	// implies it runs in an infinite loop until stopped)
	go run(mockProcessor, mockSignalHandler, mockCleaner, mockExiter)

	// Test that run() installed the signal handler
	if !<-mockSignalHandler.installCalled {
		t.Error("expected SignalHandler to be installed, but was not")
	}

	// Test that run() registered the done channel with the processor
	if !<-mockProcessor.registerDoneChannelCalled {
		t.Error("expected done channel to be registered, but was not")
	}

	// Test that run() ran the cleaner
	if !<-mockCleaner.cleanupAllCalled {
		t.Error("expected cleanupAll() to be called, but was not")
	}

	// Test that run() ran the exiter
	if !<-mockExiter.exitOnErrorCalled {
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

func TestEventerRegisteredWithCleaner(t *testing.T) {
	mockPluginLoaderForEventer := new(mockPluginLoader)
	mockPluginLoaderForSinker := new(mockSinkerLoader)
	mockCleaner := newMockCleaner()
	initPlugins()
}

func TestSinkerRegisteredWithCleaner(t *testing.T) {

}

func TestEventerCleanedUpOnSinkerInitFailure(t *testing.T) {

}
