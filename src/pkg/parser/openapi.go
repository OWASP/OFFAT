package parser

import (
	"errors"
	"strings"
	"sync"

	"github.com/OWASP/OFFAT/src/pkg/utils"
	"github.com/getkin/kin-openapi/openapi3"
	"github.com/rs/zerolog/log"
	"github.com/valyala/fasthttp"
)

const (
	ParameterInBody   = "body"
	ParameterInCookie = openapi3.ParameterInCookie
	ParameterInPath   = openapi3.ParameterInPath
	ParameterInHeader = openapi3.ParameterInHeader
	ParameterInQuery  = openapi3.ParameterInQuery
)

type OpenApi struct {
	doc           *openapi3.T
	BaseUrl       *string
	DocHttpParams []*DocHttpParams
}

func (o *OpenApi) SetDoc(doc interface{}) error {
	if doc == nil {
		return errors.New("doc ptr cannot be nil")
	}

	t, ok := doc.(*openapi3.T)
	if !ok {
		return errors.New("invalid type, SetDoc expects type *openapi3.T")
	}

	o.doc = t
	return nil
}

// assigns openapi3 params to their respective params (path, cookie, header, query)
func (o *OpenApi) AssignParamsToSlices(params openapi3.Parameters, httpPathParams, cookieParams, headerParams, queryParams, bodyParams *[]Param) {
	for _, param := range params {
		requestParam := Param{
			In:       param.Value.In,
			Name:     param.Value.Name,
			Required: param.Value.Required,
			Type:     param.Value.Schema.Value.Type.Slice(),
		}

		switch param.Value.In {
		case ParameterInPath:
			*httpPathParams = append(*httpPathParams, requestParam)
		case ParameterInCookie:
			*cookieParams = append(*cookieParams, requestParam)
		case ParameterInHeader:
			*headerParams = append(*headerParams, requestParam)
		case ParameterInQuery:
			*queryParams = append(*queryParams, requestParam)
		case ParameterInBody:
			*bodyParams = append(*bodyParams, requestParam)
		}
	}
}

func (o *OpenApi) HttpOperationToDocHttpParams(HttpMethod, path string, httpOperation *openapi3.Operation, pathParams []Param) []*DocHttpParams {
	var docHttpParams []*DocHttpParams
	var queryParams []Param
	var bodyParams []Param
	var httpPathParams []Param
	var cookieParams []Param
	var headerParams []Param
	var responseParams []Param

	// Parse Params
	if httpOperation.Parameters != nil {
		o.AssignParamsToSlices(httpOperation.Parameters, &httpPathParams, &cookieParams, &headerParams, &queryParams, &bodyParams)
	}

	// Parse Body Params
	if httpOperation.RequestBody != nil {
		for contentType, value := range httpOperation.RequestBody.Value.Content {
			for paramName, paramData := range value.Schema.Value.Properties {
				bodyParams = append(bodyParams, Param{
					Name:        paramName,
					In:          ParameterInBody,
					Required:    true, // TODO: make this hard coded value dynamic
					Type:        paramData.Value.Type.Slice(),
					ContentType: contentType,
				})
			}
		}
	}

	// // TODO: parse path params

	// Parse Security Scheme data
	var securitySchemes []map[string][]string
	if httpOperation.Security != nil {
		for _, securityRequirement := range *httpOperation.Security {
			scheme := make(map[string][]string)
			for k, v := range securityRequirement {
				scheme[k] = v
			}
			securitySchemes = append(securitySchemes, scheme)
		}
	}

	// Parse Response Data -> Body Params
	if httpOperation.Responses != nil {
		// _ -> status code
		for _, responseData := range httpOperation.Responses.Map() {
			for contentType, value := range responseData.Value.Content {
				for paramName, paramData := range value.Schema.Value.Properties {
					responseParams = append(responseParams, Param{
						Name:        paramName,
						In:          ParameterInBody,
						Required:    utils.SearchStringInSlice(paramData.Value.Required, paramName),
						Type:        paramData.Value.Type.Slice(),
						ContentType: contentType,
					})
				}
			}
		}
	}

	var url string
	if o.BaseUrl == nil {
		log.Error().Msg("field BaseUrl not set")
		url = ""
	} else {
		url = *o.BaseUrl + path
	}

	// Create DocHttpParams Instance
	docHttpParam := &DocHttpParams{
		Url:        url,
		HttpMethod: HttpMethod,
		Path:       path,
		Security:   securitySchemes,

		BodyParams:   bodyParams,
		CookieParams: cookieParams,
		HeaderParams: headerParams,
		PathParams:   append(pathParams, httpPathParams...),
		QueryParams:  queryParams,

		ResponseParams: responseParams,
	}
	docHttpParams = append(docHttpParams, docHttpParam)

	return docHttpParams
}

// Set BaseUrl for OpenApi struct
func (o *OpenApi) SetBaseUrl(baseUrl string) error {
	if utils.ValidateURL(baseUrl) {
		o.BaseUrl = &baseUrl
	} else {
		for _, server := range o.doc.Servers {
			o.BaseUrl = &server.URL
			if strings.HasPrefix(server.URL, "https://") {
				break
			}
		}

	}

	if o.BaseUrl == nil {
		return errors.New("no valid url found for baseUrl")
	}

	return nil
}

// Get Base Url
// Warning: This method should be invoked only after SetBaseUrl method
func (o *OpenApi) GetBaseUrl() *string {
	return o.BaseUrl
}

// for interface usage: configure DocHttpParams value
func (o *OpenApi) SetDocHttpParams() error {
	var docHttpParams []*DocHttpParams
	for path, pathItem := range o.doc.Paths.Map() {
		var pathParams []Param
		for _, pathParam := range pathItem.Parameters {
			pathParams = append(pathParams, Param{
				In:       pathParam.Value.In,
				Name:     pathParam.Value.Name,
				Required: pathParam.Value.Required,
			})
		}

		switch {
		case pathItem.Connect != nil:
			docHttpParams = append(docHttpParams, o.HttpOperationToDocHttpParams(fasthttp.MethodConnect, path, pathItem.Connect, pathParams)...)

		case pathItem.Delete != nil:
			docHttpParams = append(docHttpParams, o.HttpOperationToDocHttpParams(fasthttp.MethodDelete, path, pathItem.Delete, pathParams)...)

		case pathItem.Get != nil:
			docHttpParams = append(docHttpParams, o.HttpOperationToDocHttpParams(fasthttp.MethodGet, path, pathItem.Get, pathParams)...)

		case pathItem.Post != nil:
			docHttpParams = append(docHttpParams, o.HttpOperationToDocHttpParams(fasthttp.MethodPost, path, pathItem.Post, pathParams)...)

		case pathItem.Patch != nil:
			docHttpParams = append(docHttpParams, o.HttpOperationToDocHttpParams(fasthttp.MethodPatch, path, pathItem.Patch, pathParams)...)

		case pathItem.Put != nil:
			docHttpParams = append(docHttpParams, o.HttpOperationToDocHttpParams(fasthttp.MethodPut, path, pathItem.Put, pathParams)...)

		case pathItem.Head != nil:
			docHttpParams = append(docHttpParams, o.HttpOperationToDocHttpParams(fasthttp.MethodHead, path, pathItem.Head, pathParams)...)

		case pathItem.Options != nil:
			docHttpParams = append(docHttpParams, o.HttpOperationToDocHttpParams(fasthttp.MethodOptions, path, pathItem.Options, pathParams)...)
		}
	}

	o.DocHttpParams = docHttpParams
	return nil
}

// For interface usage: to retrieve DocHttpParams value
func (o *OpenApi) GetDocHttpParams() []*DocHttpParams {
	return o.DocHttpParams
}

// Fuzz Doc Http Param Values based on type
func (o *OpenApi) FuzzDocHttpParams() {
	var wg sync.WaitGroup

	for _, httpParam := range o.DocHttpParams {
		// Increment the WaitGroup counter for each FillHttpParams call
		wg.Add(6) // Since there are 6 FillHttpParams calls

		// request params
		go func(params *[]Param) {
			defer wg.Done()
			FillHttpParams(params)
		}(&httpParam.BodyParams)

		go func(params *[]Param) {
			defer wg.Done()
			FillHttpParams(params)
		}(&httpParam.CookieParams)

		go func(params *[]Param) {
			defer wg.Done()
			FillHttpParams(params)
		}(&httpParam.HeaderParams)

		go func(params *[]Param) {
			defer wg.Done()
			FillHttpParams(params)
		}(&httpParam.PathParams)

		go func(params *[]Param) {
			defer wg.Done()
			FillHttpParams(params)
		}(&httpParam.QueryParams)

		// response params
		go func(params *[]Param) {
			defer wg.Done()
			FillHttpParams(params)
		}(&httpParam.ResponseParams)
	}

	// Wait for all FillHttpParams calls to finish
	wg.Wait()
}
