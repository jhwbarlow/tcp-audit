package event

import (
	"errors"
	"fmt"

	"github.com/jhwbarlow/tcp-audit/pkg/pluginload"
)

// EventerLoader is an interface describing objects which create/"load" an Eventer.
type EventerLoader interface {
	Load() (Eventer, error)
}

// PluginEventerLoader loads a Eventer from a plugin.
type PluginEventerLoader struct {
	loader pluginload.PluginLoader
}

func NewPluginEventerLoader(loader pluginload.PluginLoader) *PluginEventerLoader {
	return &PluginEventerLoader{loader}
}

func (pl *PluginEventerLoader) Load() (Eventer, error) {
	symbol, err := pl.loader.Load()
	if err != nil {
		return nil, fmt.Errorf("loading eventer plugin: %w", err)
	}

	if _, ok := symbol.(func() (Eventer, error)); !ok {
		return nil, errors.New("eventer plugin constructor has incorrect signature")
	}

	constructor := symbol.(func() (Eventer, error))
	return constructor()
}
