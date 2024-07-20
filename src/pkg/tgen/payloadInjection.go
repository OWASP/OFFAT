package tgen

import (
	"github.com/OWASP/OFFAT/src/pkg/parser"
	c "github.com/dmdhrumilmistry/fasthttpclient/client"
	"github.com/rs/zerolog/log"
)

// injects payload in HTTP parser.param.
// It's being used in `injectParamIntoApiTest` function
func injectParamInParam(params *[]parser.Param, payload string) {
	for i := range *params {
		param := &(*params)[i]
		if len(param.Type) == 0 {
			log.Warn().Msgf("skipping payload %s injection for %v since type is missing", payload, param)
			continue
		}
		switch param.Type[0] {
		case "string":
			param.Value = payload
		}
	}
}

// generates Api tests based on provided payloads
func injectParamIntoApiTest(url string, docParams []*parser.DocHttpParams, queryParams map[string]string, headers map[string]string, testName string, vulnResponseCodes, immuneResponseCodes []int, injectionConfig InjectionConfig) []*ApiTest {
	var tests []*ApiTest
	for _, payload := range injectionConfig.Payloads {
		for _, docParam := range docParams {
			// inject payloads into string before converting it to map[string]string
			if injectionConfig.InBody {
				injectParamInParam(&(docParam.BodyParams), payload)
			}
			if injectionConfig.InQuery {
				injectParamInParam(&(docParam.QueryParams), payload)
			}
			if injectionConfig.InCookie {
				injectParamInParam(&(docParam.CookieParams), payload)
			}
			if injectionConfig.InHeader {
				injectParamInParam(&(docParam.HeaderParams), payload)
			}

			// parse maps
			url, headersMap, queryMap, bodyData, pathWithParams, err := httpParamToRequest(url, docParam, queryParams, headers, JSON)
			if err != nil {
				log.Error().Err(err).Msgf("failed to generate request params from DocHttpParams, skipping test for this case %v due to error %v", *docParam, err)
				continue
			}

			request := c.NewRequest(url, docParam.HttpMethod, queryMap, headersMap, bodyData)

			test := ApiTest{
				TestName:                testName,
				Request:                 request,
				Path:                    docParam.Path,
				PathWithParams:          pathWithParams,
				VulnerableResponseCodes: vulnResponseCodes,
				ImmuneResponseCodes:     immuneResponseCodes,
			}
			tests = append(tests, &test)
		}
	}

	return tests
}
