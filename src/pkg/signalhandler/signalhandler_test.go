package signalhandler

import (
	"os"
	"testing"

	"golang.org/x/sys/unix"
)

func TestUnixSignalHandler(t *testing.T) {
	handler := NewUnixSignalHandler()
	signalChan, done := handler.Install(unix.SIGUSR2)

	process, _ := os.FindProcess(os.Getpid())
	process.Signal(unix.SIGUSR2)

	_, open := <-done
	if open {
		t.Error("expected closed done channel, but was not")
	}

	signal := <-signalChan
	if signal != unix.SIGUSR2 {
		t.Errorf("expected signal %q, got signal %q", unix.SIGUSR2, signal)
	}

	t.Logf("got signal %q", signal)
}
