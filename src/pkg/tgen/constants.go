package tgen

import "github.com/valyala/fasthttp"

var HttpMethodsSlice = []string{
	fasthttp.MethodGet,
	fasthttp.MethodHead,
	fasthttp.MethodPost,
	fasthttp.MethodPut,
	fasthttp.MethodPatch,
	fasthttp.MethodDelete,
	fasthttp.MethodConnect,
	fasthttp.MethodOptions,
	fasthttp.MethodTrace,
}
