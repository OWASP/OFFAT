package tgen

import (
	"github.com/OWASP/OFFAT/src/pkg/parser"
	"github.com/OWASP/OFFAT/src/pkg/utils"
	c "github.com/dmdhrumilmistry/fasthttpclient/client"
	"github.com/rs/zerolog/log"
)

func BolaTest(baseUrl string, docParams []*parser.DocHttpParams, queryParams map[string]string, headers map[string]string) []*ApiTest {
	var tests []*ApiTest
	testName := "BOLA Test"
	immuneResponseCode := []int{404, 405} // 502, 503, 504 -> responses could lead to DoS using the endpoint

	for _, docParam := range docParams {
		// skip test generation if there are no path params
		if len(docParam.PathParams) < 1 {
			continue
		}

		url, headersMap, queryMap, bodyData, pathWithParams, err := httpParamToRequest(baseUrl, docParam, queryParams, headers, utils.JSON)
		if err != nil {
			log.Error().Err(err).Msgf("failed to generate request params from DocHttpParams, skipping test for this case %v due to error %v", *docParam, err)
			continue
		}

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
