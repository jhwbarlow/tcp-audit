package main

import (
	"os"
	"syscall"
)

type exiter interface {
	exitOnError()
	exitOnSignal(signal os.Signal)
}

type unixExiter struct{}

func (*unixExiter) exitOnError() {
	os.Exit(1)
}

// ExitOnSignal exits the process and encodes the signal number received into the
// exit code in the traditional Unix style.
// See https://tldp.org/LDP/abs/html/exitcodes.html
func (*unixExiter) exitOnSignal(signal os.Signal) {
	exitCode := 0
	if signal, ok := signal.(syscall.Signal); ok {
		exitCode = 128 + int(signal)
	}

	os.Exit(exitCode)
}
