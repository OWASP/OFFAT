package utils

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/rs/zerolog/log"
	"gopkg.in/yaml.v3"
)

const JSON = "json"
const YAML = "yaml"
const XML = "xml"

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

// Infer content type based on URI/file path
func InferContentTypeByPath(filename string) (string, error) {
	var contentType string

	switch {
	case strings.HasSuffix(filename, ".json"):
		contentType = JSON
	case strings.HasSuffix(filename, ".yaml") || strings.HasSuffix(filename, ".yml"):
		contentType = YAML
	default:
		err := fmt.Errorf("invalid file extension")
		log.Error().Stack().Err(err).Msg("Failed to infer API documentation Content Type")
		return "", err
	}

	return contentType, nil
}

// detects JSON/YAML content type. returns error if no match is found
func DetectContentType(content []byte) (string, error) {
	// Try to unmarshal as JSON
	var js json.RawMessage
	if json.Unmarshal(content, &js) == nil {
		return JSON, nil
	}

	// Try to unmarshal as YAML
	var yml interface{}
	if yaml.Unmarshal(content, &yml) == nil {
		return YAML, nil
	}

	return "", fmt.Errorf("content type is not JSON/YAML")

}
