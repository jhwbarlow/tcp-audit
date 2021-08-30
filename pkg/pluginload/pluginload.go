package pluginload

import (
	"fmt"
	"plugin"
)

type PluginLoader interface {
	Load() (plugin.Symbol, error)
}

type FilesystemSharedObjectPluginLoader struct {
	path string
}

func NewFilesystemSharedObjectPluginLoader(path string) *FilesystemSharedObjectPluginLoader {
	return &FilesystemSharedObjectPluginLoader{path}
}

func (fl *FilesystemSharedObjectPluginLoader) Load() (plugin.Symbol, error) {
	plugin, err := plugin.Open(fl.path)
	if err != nil {
		return nil, fmt.Errorf("opening plugin: %w", err)
	}

	symbol, err := plugin.Lookup("New")
	if err != nil {
		return nil, fmt.Errorf("plugin has no constructor: %w", err)
	}

	return symbol, nil
}
