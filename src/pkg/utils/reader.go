package utils

import (
	"encoding/json"
	"errors"
	"os"

	"gopkg.in/yaml.v2"
)

const JSON = "json"
const YAML = "yaml"

// Loads JSON/YAML file into holder ptr based on contentType
// Note: function assumes that user has already validated filename
func LoadJsonYamlFromFile(filename string, holder any, contentType string) error {

	data, err := os.ReadFile(filename)
	if err != nil {
		return err
	}

	return LoadJsonYaml(data, holder, contentType)
}

// Parses JSON/YAML file content into holder ptr based on contentType
func LoadJsonYaml(filedata []byte, holder any, contentType string) error {
	var decoder func([]byte, any) error
	switch contentType {
	case JSON:
		decoder = json.Unmarshal
	case YAML:
		decoder = yaml.Unmarshal
	default:
		return errors.New("invaid contentType, only json and yaml are supported")
	}

	if err := decoder([]byte(filedata), holder); err != nil {
		return err
	}

	return nil
}
