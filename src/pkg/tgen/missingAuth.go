package tgen

import (
	"github.com/OWASP/OFFAT/src/pkg/parser"
	"github.com/OWASP/OFFAT/src/pkg/utils"
	c "github.com/dmdhrumilmistry/fasthttpclient/client"
	"github.com/rs/zerolog/log"
)

func MissingAuthTest(baseUrl string, docParams []*parser.DocHttpParams, queryParams map[string]string, headers map[string]string) []*ApiTest {
	var tests []*ApiTest
	testName := "Missing Auth Implementation Test"
	immuneResponseCode := []int{401, 403, 404, 405}
	authKeys := []string{
		"Authorization",
		"authorization",
		"X-API-Key",
		"x-api-key",
		"API_KEY",
		"api_key",
	}

	for _, docParam := range docParams {
		// skip test generation if there are no security schemes
		if len(docParam.Security) < 1 {
			continue
		}

		url, headersMap, queryMap, bodyData, pathWithParams, err := httpParamToRequest(baseUrl, docParam, queryParams, headers, utils.JSON)
		if err != nil {
			log.Error().Err(err).Msgf("failed to generate request params from DocHttpParams, skipping test for this case %v due to error %v", *docParam, err)
			continue
		}

		// Delete auth data from header and query
		DeleteAuthFromMap(headersMap, authKeys)
		DeleteAuthFromMap(queryMap, authKeys)

		request := c.NewRequest(url, docParam.HttpMethod, queryMap, headersMap, bodyData)

		test := ApiTest{
			TestName:            testName,
			Request:             request,
			Path:                docParam.Path,
			PathWithParams:      pathWithParams,
			ImmuneResponseCodes: immuneResponseCode,
		}
		tests = append(tests, &test)
	}

	return tests
}

func DeleteAuthFromMap(authMap map[string]string, keys []string) {
	for _, key := range keys {
		delete(authMap, key)
	}
}
