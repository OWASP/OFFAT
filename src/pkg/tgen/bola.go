package tgen

import (
	"path"
	"strconv"
	"strings"

	"github.com/OWASP/OFFAT/src/pkg/fuzzer"
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

func BolaTrailingPathTest(baseUrl string, docParams []*parser.DocHttpParams, queryParams map[string]string, headers map[string]string) []*ApiTest {
	var tests []*ApiTest
	testName := "BOLA Trailing Path Test"
	immuneResponseCode := []int{404, 405} // 502, 503, 504 -> responses could lead to DoS using the endpoint

	for _, docParam := range docParams {
		url, headersMap, queryMap, bodyData, pathWithParams, err := httpParamToRequest(baseUrl, docParam, queryParams, headers, utils.JSON)
		if err != nil {
			log.Error().Err(err).Msgf("failed to generate request params from DocHttpParams, skipping test for this case %v due to error %v", *docParam, err)
			continue
		}

		randNum, err := fuzzer.GenerateRandomIntInRange(1, 1000)
		if err != nil {
			log.Error().Err(err).Msgf("failed to generate random id for Trailing BOLA Path Test, skipping test generation for this case %v due to error %v", *docParam, err)
			continue
		}
		randomId := strconv.Itoa(randNum)

		// add random digit as id at the end of current path
		uriPath := path.Join(docParam.Path, randomId)
		url = strings.ReplaceAll(path.Join(url, randomId), ":/", "://")

		// prepare test request
		request := c.NewRequest(url, docParam.HttpMethod, queryMap, headersMap, bodyData)

		test := ApiTest{
			TestName:            testName,
			Request:             request,
			Path:                uriPath,
			PathWithParams:      pathWithParams,
			ImmuneResponseCodes: immuneResponseCode,
		}
		tests = append(tests, &test)
	}

	return tests
}
