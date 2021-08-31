package main

import (
	"testing"

	"github.com/jhwbarlow/tcp-audit-common/pkg/event"
)

type mockEventerCloser struct {
	closeCalled bool
}

func (*mockEventerCloser) Event() (*event.Event, error) {
	return nil, nil
}

func (mec *mockEventerCloser) Close() error {
	mec.closeCalled = true
	return nil
}

type mockSinkerCloser struct {
	closeCalled bool
}

func (*mockSinkerCloser) Sink(*event.Event) error {
	return nil
}

func (msc *mockSinkerCloser) Close() error {
	msc.closeCalled = true
	return nil
}

func TestCleanerCleansEventer(t *testing.T) {
	mockEventerCloser := new(mockEventerCloser)

	cleaner := new(closingCleaner)
	cleaner.registerEventer(mockEventerCloser)
	cleaner.cleanupEventer()

	if !mockEventerCloser.closeCalled {
		t.Error("expected eventerCloser to be closed, but was not")
	}
}

func TestCleanerCleansSinker(t *testing.T) {
	mockSinkerCloser := new(mockSinkerCloser)

	cleaner := new(closingCleaner)
	cleaner.registerSinker(mockSinkerCloser)
	cleaner.cleanupSinker()

	if !mockSinkerCloser.closeCalled {
		t.Error("expected sinkerrCloser to be closed, but was not")
	}
}

func TestCleanerCleansAll(t *testing.T) {
	mockSinkerCloser := new(mockSinkerCloser)
	mockEventerCloser := new(mockEventerCloser)

	cleaner := new(closingCleaner)
	cleaner.registerEventer(mockEventerCloser)
	cleaner.registerSinker(mockSinkerCloser)
	cleaner.cleanupAll()

	if !mockEventerCloser.closeCalled {
		t.Error("expected eventerCloser to be closed, but was not")
	}

	if !mockSinkerCloser.closeCalled {
		t.Error("expected sinkerrCloser to be closed, but was not")
	}
}
