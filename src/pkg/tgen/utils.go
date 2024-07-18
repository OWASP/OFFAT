package tgen

import (
	"fmt"

	"github.com/OWASP/OFFAT/src/pkg/parser"
	"github.com/rs/zerolog/log"
)

// convert parser.Param to map
func ParamsToMap(params []parser.Param) map[string]interface{} {
	paramMap := make(map[string]interface{})

	for _, param := range params {
		paramMap[param.Name] = param.Value
	}

	return paramMap
}

// MergeMaps merges two maps and returns a map[string]string and an error if any value in map2 cannot be converted to a string
func MergeMaps(map1 map[string]string, map2 map[string]interface{}) map[string]string {
	mergedMap := map[string]string{}

	// Copy all key-value pairs from map1 to mergedMap
	for k, v := range map1 {
		mergedMap[k] = v
	}

	// Copy all key-value pairs from map2 to mergedMap, checking types
	for k, v := range map2 {
		strValue, ok := v.(string)
		if !ok {
			log.Error().Stack().Err(fmt.Errorf("failed to convert %v to string", v))
			continue
		}
		mergedMap[k] = strValue
	}

	return mergedMap
}
