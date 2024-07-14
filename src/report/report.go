package report

import (
	"encoding/json"
	"fmt"

	"github.com/OWASP/OFFAT/src/pkg/tgen"
)

const JSON = "json"

func Report(apiTests []*tgen.ApiTest, contentType string) ([]byte, error) {
	switch contentType {
	case JSON:
		return json.Marshal(&apiTests)
	default:
		return nil, fmt.Errorf("invalid report content type")
	}
}
