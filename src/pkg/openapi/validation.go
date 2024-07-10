package openapi

import (
	"errors"
	"log"
	"strings"

	"github.com/OWASP/OFFAT/src/pkg/utils"
	"github.com/getkin/kin-openapi/openapi2"
	"github.com/getkin/kin-openapi/openapi3"
)

type Parser struct {
	Version               string
	Filename              string
	IsOpenApi             bool // else Swagger
	IsExternalRefsAllowed bool

	// OAS validation opts
	DisableExamplesValidation       bool
	DisableSchemaDefaultsValidation bool
	DisableSchemaPatternValidation  bool

	// Parsed Docs
	OpenApiDoc *openapi3.T
	SwaggerDoc *openapi2.T
}

func (p *Parser) Parse(filename string) (err error) {
	var contentType string
	switch {
	case strings.HasSuffix(filename, ".json"):
		contentType = utils.JSON
	case strings.HasSuffix(filename, ".yaml") || strings.HasSuffix(filename, ".yml"):
		contentType = utils.YAML
	default:
		return errors.New("invalid file extension")
	}

	// Detect Doc Version
	var head struct {
		OpenAPI string `json:"openapi" yaml:"openapi"`
		Swagger string `json:"swagger" yaml:"swagger"`
	}

	if err := utils.Read(filename, &head, contentType); err != nil {
		return err
	}

	if head.OpenAPI != "" {
		p.Version = head.OpenAPI
		p.IsOpenApi = true
	} else if head.Swagger != "" {
		p.Version = head.Swagger
	} else {
		return errors.New("invalid OAS/swagger version")
	}

	// Parse documentation
	switch {
	case p.Version == "3" || strings.HasPrefix(p.Version, "3."):
		loader := openapi3.NewLoader()
		loader.IsExternalRefsAllowed = p.IsExternalRefsAllowed

		doc, err := loader.LoadFromFile(p.Filename)
		if err != nil {
			log.Fatalln("Loading error:", err)
			return err
		}

		var opts []openapi3.ValidationOption
		if p.DisableExamplesValidation {
			opts = append(opts, openapi3.DisableSchemaDefaultsValidation())
		}
		if p.DisableExamplesValidation {
			opts = append(opts, openapi3.DisableExamplesValidation())
		}
		if p.DisableSchemaPatternValidation {
			opts = append(opts, openapi3.DisableSchemaPatternValidation())
		}

		if err = doc.Validate(loader.Context, opts...); err != nil {
			log.Fatalln("Validation error:", err)
		}
		p.OpenApiDoc = doc

	case p.Version == "2" || strings.HasPrefix(p.Version, "2."):
		var doc openapi2.T
		if err := utils.Read(filename, &doc, contentType); err != nil {
			return err
		}
		p.SwaggerDoc = &doc

	default:
		return errors.New("missing or incorrect 'openapi' or 'swagger' field")
	}

	return nil
}
