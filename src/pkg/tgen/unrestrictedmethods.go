// Tests for unrestricted HTTP methods/verbs
package tgen

import (
	_ "github.com/OWASP/OFFAT/src/pkg/logging"
	"github.com/OWASP/OFFAT/src/pkg/parser"
	"github.com/OWASP/OFFAT/src/pkg/utils"
	c "github.com/dmdhrumilmistry/fasthttpclient/client"
	"github.com/rs/zerolog/log"
)

// returns a new map with k:parser.DocHttpParams.Name, v:parser.DocHttpParams.Value
func UnrestrictedHttpMethods(baseUrl string, docParams []*parser.DocHttpParams, queryParams map[string]string, headers map[string]string) []*ApiTest {
	var tests []*ApiTest
	testName := "Unrestricted HTTP Methods/Verbs"
	immuneResponseCode := []int{404, 405} // 502, 503, 504 -> responses could lead to DoS using the endpoint

	for _, docParam := range docParams {
		url, headersMap, queryMap, bodyData, pathWithParams, err := httpParamToRequest(baseUrl, docParam, queryParams, headers, utils.JSON)
		if err != nil {
			log.Error().Err(err).Msgf("failed to generate request params from DocHttpParams, skipping test for this case %v due to error %v", *docParam, err)
			continue
		}
		for _, httpMethod := range utils.RemoveElement(HttpMethodsSlice, docParam.HttpMethod) {
			request := c.NewRequest(url, httpMethod, queryMap, headersMap, bodyData)

			test := ApiTest{
				TestName:            testName,
				Request:             request,
				Path:                docParam.Path,
				PathWithParams:      pathWithParams,
				ImmuneResponseCodes: immuneResponseCode,
			}
			tests = append(tests, &test)
		}
	}

	return tests
}
