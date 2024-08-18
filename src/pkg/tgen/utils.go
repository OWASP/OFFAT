package tgen

import (
	"encoding/json"
	"encoding/xml"
	"fmt"
	neturl "net/url"
	"strings"

	"github.com/OWASP/OFFAT/src/pkg/parser"
	"github.com/OWASP/OFFAT/src/pkg/utils"
	"github.com/rs/zerolog/log"
)

// convert parser.Param to map
func ParamsToMap(params []parser.Param) map[string]string {
	paramMap := make(map[string]string)

	for _, param := range params {
		paramMap[param.Name] = fmt.Sprintf("%v", param.Value)
	}

	return paramMap
}

// MergeMaps merges two maps and returns a map[string]string and an error if any value in map2 cannot be converted to a string
func MergeMaps(map1 map[string]string, map2 map[string]string) map[string]string {
	mergedMap := map[string]string{}

	// Copy all key-value pairs from map1 to mergedMap
	for k, v := range map1 {
		mergedMap[k] = v
	}

	// Copy all key-value pairs from map2 to mergedMap
	for k, v := range map2 {
		mergedMap[k] = v
	}

	return mergedMap
}

func mapToCookieHeader(cookieMap map[string]string) string {
	var cookies []string
	for key, value := range cookieMap {
		cookies = append(cookies, fmt.Sprintf("%s=%s", key, value))
	}
	return strings.Join(cookies, "; ")
}

// converts doc http param into headers (map[string]string), query (map[string]string),
func httpParamToRequest(baseUrl string, docParam *parser.DocHttpParams, queryParams map[string]string, headers map[string]string, bodyContentType string) (url string, headersMap map[string]string, queryMap map[string]string, bodyData []byte, pathWithParams string, err error) {
	// parse params and convert it to map[string]string{}
	parsedbodyMap := ParamsToMap(docParam.BodyParams)
	parsedQueryParamsMap := ParamsToMap(docParam.QueryParams)
	parsedHeaderParamsMap := ParamsToMap(docParam.HeaderParams)
	parsedPathParamsMap := ParamsToMap(docParam.PathParams)
	parsedCookieParams := ParamsToMap(docParam.CookieParams)

	// combine maps with default values
	headersMap = MergeMaps(headers, parsedHeaderParamsMap)
	queryMap = MergeMaps(queryParams, parsedQueryParamsMap)

	// populate path params
	pathWithParams = docParam.Path
	for pathParam, pathParamValue := range parsedPathParamsMap {
		pathWithParams = strings.ReplaceAll(pathWithParams, "{"+pathParam+"}", pathParamValue)
	}

	url, err = neturl.JoinPath(baseUrl, pathWithParams)
	if err != nil {
		log.Warn().Stack().Err(err).Msgf("failed to join url path %v,%v, using default doc param url %v", baseUrl, pathWithParams, docParam.Url)
		url = docParam.Url
	}

	// handle cookie params
	cookieHeaderValue := mapToCookieHeader(parsedCookieParams)
	if currentCookieHeaderValue, exists := headersMap["Cookies"]; exists {
		cookieHeaderValue = currentCookieHeaderValue + cookieHeaderValue
		headersMap["Cookies"] = cookieHeaderValue
	}

	// convert body to JSON
	switch bodyContentType {
	case utils.JSON:
		headersMap["Content-Type"] = "application/json"
		bodyData, err = json.Marshal(parsedbodyMap)
		if err != nil {
			log.Error().Stack().Err(err).Msgf("failed to convert bodyMap to %s", utils.JSON)
			bodyData = nil
		}

	case utils.XML:
		// TODO: fix errs
		headersMap["Content-Type"] = "application/xml"
		bodyData, err = xml.MarshalIndent(parsedbodyMap, "", "")
		if err != nil {
			log.Error().Stack().Err(err).Msgf("failed to convert bodyMap to %s", utils.XML)
			bodyData = nil
		}
	default:
		log.Warn().Msgf("invalid content type %v, using default value for bodyData: nil", bodyContentType)
		bodyData = nil
	}

	return url, headersMap, queryMap, bodyData, pathWithParams, nil
}
