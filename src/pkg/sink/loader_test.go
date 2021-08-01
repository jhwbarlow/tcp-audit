package sink

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

func TestLoadSinker(t *testing.T) {
	mockConstructorSymbol := func() (Sinker, error) {
		return nil, nil
	}

	mockPluginLoader := &mockPluginLoader{symbolToReturn: mockConstructorSymbol}
	loader := NewPluginSinkerLoader(mockPluginLoader)
	_, err := loader.Load()
	if err != nil {
		t.Errorf("expected nil error, got %v (of type %T)", err, err)
	}
}

func TestLoadSinkerBadConstructorSignature(t *testing.T) {
	mockConstructorSymbol := func() {}

	mockPluginLoader := &mockPluginLoader{symbolToReturn: mockConstructorSymbol}
	loader := NewPluginSinkerLoader(mockPluginLoader)
	_, err := loader.Load()
	if err == nil {
		t.Error("expected error, nil")
	}

	t.Logf("got error %v (of type %T)", err, err)
}

func TestLoadSinkerPluginLoaderError(t *testing.T) {
	mockErr := errors.New("mock plugin loader error")

	mockPluginLoader := &mockPluginLoader{errorToReturn: mockErr}
	loader := NewPluginSinkerLoader(mockPluginLoader)
	_, err := loader.Load()
	if err == nil {
		t.Error("expected error, got nil")
	}

	// The sinker loader should return an error with the plugin loader
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
