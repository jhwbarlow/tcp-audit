package signalhandler

import (
	"os"
	"os/signal"
)

// SignalHandler is an interface which describes objects which emit a signal and
// simultaneously closes the done channel.
type SignalHandler interface {
	Install(signals ...os.Signal) (signalChan <-chan os.Signal, done <-chan struct{})
}

// OSSignalHandler handles signals that originate from the operating system.
type OSSignalHandler struct{}

func NewOSSignalHandler() *OSSignalHandler {
	return new(OSSignalHandler)
}

// Install installs this handler for the given signals.
// When a signal arrives, it is sent on the returned channel and the returned done channel
// is also closed.
func (*OSSignalHandler) Install(signals ...os.Signal) (signalChan <-chan os.Signal, done <-chan struct{}) {
	signalChanIn := make(chan os.Signal, 1)
	signal.Notify(signalChanIn, signals...)
	signalChanOut := make(chan os.Signal, 1)
	doneOut := make(chan struct{})

	go func(done chan<- struct{},
		signalChanIn <-chan os.Signal,
		signalChanOut chan<- os.Signal) {
		signalChanOut <- <-signalChanIn
		close(done)
	}(doneOut, signalChanIn, signalChanOut)

	return signalChanOut, doneOut
}
