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

func (*unixExiter) exitOnSignal(signal os.Signal) {
	exitCode := 0
	if signal, ok := signal.(syscall.Signal); ok {
		exitCode = 127 + int(signal)
	}

	os.Exit(exitCode)
}
