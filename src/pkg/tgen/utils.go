package tgen

import "github.com/OWASP/OFFAT/src/pkg/parser"

// convert parser.Param to map
func ParamsToMap(params []parser.Param) map[string]interface{} {
	paramMap := make(map[string]interface{})

	for _, param := range params {
		paramMap[param.Name] = param.Value
	}

	return paramMap
}
