package sink

import (
	"errors"
	"fmt"

	"github.com/jhwbarlow/tcp-audit/pkg/pluginload"
)

// SinkerLoader is an interface describing objects which create/"load" a Sinker.
type SinkerLoader interface {
	Load() (Sinker, error)
}

// PluginSinkerLoader loads a Sinker from a plugin.
type PluginSinkerLoader struct {
	loader pluginload.PluginLoader
}

func NewPluginSinkerLoader(loader pluginload.PluginLoader) *PluginSinkerLoader {
	return &PluginSinkerLoader{loader}
}

func (pl *PluginSinkerLoader) Load() (Sinker, error) {
	symbol, err := pl.loader.Load()
	if err != nil {
		return nil, fmt.Errorf("loading sinker plugin: %w", err)
	}

	if _, ok := symbol.(func() (Sinker, error)); !ok {
		return nil, errors.New("sinker plugin constructor has incorrect signature")
	}

	constructor := symbol.(func() (Sinker, error))
	return constructor()
}
