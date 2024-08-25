package tgen

import (
	"github.com/OWASP/OFFAT/src/pkg/parser"
	"github.com/OWASP/OFFAT/src/pkg/utils"
	c "github.com/dmdhrumilmistry/fasthttpclient/client"
	"github.com/rs/zerolog/log"
)

// injects payload in HTTP parser.param based on type/value
// It's being used in `injectParamIntoApiTest` function
func injectParamInParam(params *[]parser.Param, payload string) {
	for i := range *params {
		var paramType string
		param := &(*params)[i]
		if len(param.Type) == 0 && param.Value == nil {
			log.Warn().Msgf("skipping payload %s injection for %v since type/value is missing", payload, param)
			continue
		} else if len(param.Type) == 0 {
			log.Warn().Msgf("injecting payload %s in %v with missing type", payload, param)
			paramType = "random"
		} else {
			paramType = param.Type[0]
		}

		switch paramType {
		case "string", "random":
			param.Value = payload
		}
	}
}

// generates Api tests by injecting payloads in values
func injectParamIntoApiTest(url string, docParams []*parser.DocHttpParams, queryParams map[string]string, headers map[string]string, testName string, injectionConfig InjectionConfig) []*ApiTest {
	var tests []*ApiTest
	// TODO: only inject payloads if any payload is accepted by the endpoint, else ignore injection
	// as this will reduce number of tests generated and increase efficiency
	for _, payload := range injectionConfig.Payloads {
		// TODO: implement injection in both key or value at a time
		for _, docParam := range docParams {
			// inject payloads into string before converting it to map[string]string
			if injectionConfig.InBody {
				injectParamInParam(&(docParam.BodyParams), payload.InjText)
			}
			if injectionConfig.InQuery {
				injectParamInParam(&(docParam.QueryParams), payload.InjText)
			}
			if injectionConfig.InCookie {
				injectParamInParam(&(docParam.CookieParams), payload.InjText)
			}
			if injectionConfig.InHeader {
				injectParamInParam(&(docParam.HeaderParams), payload.InjText)
			}

			// parse maps
			url, headersMap, queryMap, bodyData, pathWithParams, err := httpParamToRequest(url, docParam, queryParams, headers, utils.JSON)
			if err != nil {
				log.Error().Err(err).Msgf("failed to generate request params from DocHttpParams, skipping test for this case %v due to error %v", *docParam, err)
				continue
			}

			// check for uri endpoint injection in query param for vulnerable endpoint detection/backtracking
			// this is required since all endpoints will make call to same ssrf payload
			// so in order to detect vulnerable endpoint inject its uri path in query param
			// example: https://ssrf-website.com?offat_test_endpoint=/api/v1/users

			if injectionConfig.InjectUriInQuery {
				queryMap["offat_test_endpoint"] = docParam.Path
			}

			request := c.NewRequest(url, docParam.HttpMethod, queryMap, headersMap, bodyData)

			test := ApiTest{
				TestName:                testName,
				Request:                 request,
				Path:                    docParam.Path,
				PathWithParams:          pathWithParams,
				VulnerableResponseCodes: payload.VulnerableResponseCodes,
				ImmuneResponseCodes:     payload.ImmuneResponseCodes,
				MatchRegex:              payload.Regex,
			}
			tests = append(tests, &test)
		}
	}

	return tests
}
