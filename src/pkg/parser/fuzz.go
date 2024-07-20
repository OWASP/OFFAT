package parser

import (
	"sync"

	"github.com/OWASP/OFFAT/src/pkg/fuzzer"
	_ "github.com/OWASP/OFFAT/src/pkg/logging"
	"github.com/rs/zerolog/log"
)

// Fill parser.Param.Value based on parser.Param.Type (type considers first value of the list)
func FillHttpParam(param *Param) bool {
	var paramType string
	if len(param.Type) == 0 {
		log.Warn().Msgf("param %v doesn't have any specified type, random str will be used as value", param)
		paramType = "random"
	} else {
		paramType = param.Type[0]
	}

	switch paramType {
	case "string":
		value, err := fuzzer.FuzzStringType(param.Name)
		if err != nil {
			log.Error().Stack().Err(err).Msgf("failed to fuzz string with param name %s", param.Name)
			return false
		}
		param.Value = value

	case "integer":
		value, err := fuzzer.GenerateRandomIntInRange(0, 100)
		if err != nil {
			log.Error().Stack().Err(err).Msgf("failed to fuzz int with param name %s", param.Name)
			return false
		}
		param.Value = value

	case "boolean":
		param.Value = fuzzer.GenerateRandomBoolean()

	case "array":
		value, err := fuzzer.FuzzStringType(param.Name)
		if err != nil {
			log.Error().Stack().Err(err).Msgf("failed to fuzz string with param name %s", param.Name)
			return false
		}
		param.Value = []string{value}

	// TODO: handle object type
	// case "object":

	default: // fill random string
		value, err := fuzzer.GenerateRandomString(10)
		if err != nil {
			log.Error().Stack().Err(err).Msgf("failed to fuzz int with param name %s", param.Name)
			return false
		}
		param.Value = value
	}

	return true
}

// concurrently fills http params
func FillHttpParams(params *[]Param) {
	var wg sync.WaitGroup
	for i := range *params {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			if !FillHttpParam(&(*params)[idx]) { // Pass a pointer to the Param element
				log.Error().Msgf("failed to populate value %v:", (*params)[idx])
			}
		}(i)
	}
	wg.Wait()
}
