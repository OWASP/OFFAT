package utils

import (
	"encoding/json"
	"errors"
	"os"

	"gopkg.in/yaml.v2"
)

const JSON = "json"
const YAML = "yaml"

// Parses JSON/YAML files
// Note: function assumes that user has already validated filename
func Read(filename string, holder any, contentType string) error {
	data, err := os.ReadFile(filename)
	if err != nil {
		return err
	}

	var decoder func([]byte, any) error
	switch contentType {
	case JSON:
		decoder = json.Unmarshal
	case YAML:
		decoder = yaml.Unmarshal
	default:
		return errors.New("invaid contentType, only json and yaml are supported")
	}

	if err := decoder(data, holder); err != nil {
		return err
	}
	return nil
}
