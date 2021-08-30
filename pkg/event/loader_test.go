package event

import (
	"errors"
	"plugin"
	"testing"
)

type mockPluginLoader struct {
	errorToReturn  error
	symbolToReturn plugin.Symbol
}

func (mpl *mockPluginLoader) Load() (plugin.Symbol, error) {
	if mpl.errorToReturn != nil {
		return nil, mpl.errorToReturn
	}

	return mpl.symbolToReturn, nil
}

func TestLoadEventer(t *testing.T) {
	mockConstructorSymbol := func() (Eventer, error) {
		return nil, nil
	}

	mockPluginLoader := &mockPluginLoader{symbolToReturn: mockConstructorSymbol}
	loader := NewPluginEventerLoader(mockPluginLoader)
	_, err := loader.Load()
	if err != nil {
		t.Errorf("expected nil error, got %v (of type %T)", err, err)
	}
}

func TestLoadEventerBadConstructorSignature(t *testing.T) {
	mockConstructorSymbol := func() {}

	mockPluginLoader := &mockPluginLoader{symbolToReturn: mockConstructorSymbol}
	loader := NewPluginEventerLoader(mockPluginLoader)
	_, err := loader.Load()
	if err == nil {
		t.Error("expected error, nil")
	}

	t.Logf("got error %v (of type %T)", err, err)
}

func TestLoadEventerPluginLoaderError(t *testing.T) {
	mockErr := errors.New("mock plugin loader error")

	mockPluginLoader := &mockPluginLoader{errorToReturn: mockErr}
	loader := NewPluginEventerLoader(mockPluginLoader)
	_, err := loader.Load()
	if err == nil {
		t.Error("expected error, got nil")
	}

	// The eventer loader should return an error with the plugin loader
	// error in the chain
	if !errors.Is(err, mockErr) {
		t.Errorf("expected error %v (of type %T), got error %v (of type %T)",
			mockErr,
			mockErr,
			err,
			err)
	}

	t.Logf("got error %v (of type %T)", err, err)
}
