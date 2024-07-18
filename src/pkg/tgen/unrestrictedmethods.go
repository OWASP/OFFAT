// Tests for unrestricted HTTP methods/verbs
package tgen

import (
	"encoding/json"

	_ "github.com/OWASP/OFFAT/src/pkg/logging"
	"github.com/OWASP/OFFAT/src/pkg/parser"
	"github.com/OWASP/OFFAT/src/pkg/utils"
	c "github.com/dmdhrumilmistry/fasthttpclient/client"
	"github.com/rs/zerolog/log"
)

// returns a new map with k:parser.DocHttpParams.Name, v:parser.DocHttpParams.Value
func UnrestrictedHttpMethods(docParams []*parser.DocHttpParams, queryParams map[string]string, headers map[string]string) []*ApiTest {
	var tests []*ApiTest
	testName := "Unrestricted HTTP Methods/Verbs"
	// successCodes := []int{200, 201, 202, 204, 301, 302, 400}
	immuneResponseCode := []int{404, 405, 502, 503, 504}

	for _, docParam := range docParams {
		// parse params and convert it to map[string]interface{}
		parsedbodyMap := ParamsToMap(docParam.BodyParams)
		parsedQueryParamsMap := ParamsToMap(docParam.QueryParams)
		parsedHeaderParamsMap := ParamsToMap(docParam.HeaderParams)
		// parsedPathParamsMap := ParamsToMap(docParam.PathParams)
		// TODO: handle cookie params

		// convert body to JSON
		jsonData, err := json.Marshal(parsedbodyMap)
		if err != nil {
			log.Error().Stack().Err(err).Msg("failed to convert bodyMap to JSON")
			jsonData = nil
		}

		// combine maps with default values
		mergedHeaderParams := MergeMaps(headers, parsedHeaderParamsMap)
		mergedQueryParams := MergeMaps(queryParams, parsedQueryParamsMap)

		for _, httpMethod := range utils.RemoveElement(HttpMethodsSlice, docParam.HttpMethod) {
			request := c.NewRequest(docParam.Url, httpMethod, mergedQueryParams, mergedHeaderParams, jsonData)

			test := ApiTest{
				TestName:            testName,
				Request:             request,
				Path:                docParam.Path,
				ImmuneResponseCodes: immuneResponseCode,
			}
			tests = append(tests, &test)
		}
	}

	return tests
}
