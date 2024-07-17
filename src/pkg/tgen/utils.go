package tgen

import (
	"reflect"

	"github.com/OWASP/OFFAT/src/pkg/parser"
)

// convert parser.Param to map
func ParamsToMap(params []parser.Param) map[string]interface{} {
	paramMap := make(map[string]interface{})

	for _, param := range params {
		paramMap[param.Name] = param.Value
	}

	return paramMap
}

func MergeMaps(dst, src any) any {
	dstVal := reflect.ValueOf(dst)
	srcVal := reflect.ValueOf(src)

	// Create a new map of the same type as dst
	result := reflect.MakeMap(dstVal.Type())

	// Copy all elements from dst to result
	for _, key := range dstVal.MapKeys() {
		result.SetMapIndex(key, dstVal.MapIndex(key))
	}

	// Overwrite or add elements from src to result
	for _, key := range srcVal.MapKeys() {
		result.SetMapIndex(key, srcVal.MapIndex(key))
	}

	return result.Interface()
}
