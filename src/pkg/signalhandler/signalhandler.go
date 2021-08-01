package signalhandler

import (
	"os"
	"os/signal"
)

type SignalHandler interface {
	Install(signals ...os.Signal) (<-chan os.Signal, <-chan struct{})
}

type UnixSignalHandler struct{}

func NewUnixSignalHandler() *UnixSignalHandler {
	return new(UnixSignalHandler)
}

func (*UnixSignalHandler) Install(signals ...os.Signal) (<-chan os.Signal, <-chan struct{}) {
	signalChanIn := make(chan os.Signal, 1)
	signal.Notify(signalChanIn, signals...)
	signalChanOut := make(chan os.Signal, 1)
	done := make(chan struct{})

	go func(done chan<- struct{},
		signalChanIn <-chan os.Signal,
		signalChanOut chan<- os.Signal) {
		signalChanOut <- <-signalChanIn
		close(done)
	}(done, signalChanIn, signalChanOut)

	return signalChanOut, done
}
