package parser

import (
	"errors"
	"os"
	"strings"

	_ "github.com/OWASP/OFFAT/src/pkg/logging"
	"github.com/OWASP/OFFAT/src/pkg/utils"

	"github.com/getkin/kin-openapi/openapi2"
	"github.com/getkin/kin-openapi/openapi3"
	"github.com/rs/zerolog/log"
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
	Doc DocInterface
}

func NewParser(filename string, isExternalRefsAllowed, disableExamplesValidation, disableSchemaDefaultsValidation, disableSchemaPatternValidation bool) (parser *Parser, err error) {

	_, err = os.Stat(filename)
	if err != nil {
		log.Error().Err(err).Msg("file not found")
		return nil, err
	}

	return &Parser{
		Filename:                        filename,
		DisableExamplesValidation:       disableExamplesValidation,
		DisableSchemaDefaultsValidation: disableSchemaDefaultsValidation,
		DisableSchemaPatternValidation:  disableSchemaPatternValidation,
		IsExternalRefsAllowed:           isExternalRefsAllowed,
	}, nil
}

// Parses and Populates file contents to Parser struct fields
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
	if p.IsOpenApi {
		loader := openapi3.NewLoader()
		loader.IsExternalRefsAllowed = p.IsExternalRefsAllowed

		doc, err := loader.LoadFromFile(p.Filename)
		if err != nil {
			log.Error().Err(err).Msg("Failed to load file")
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
			log.Error().Err(err).Msg("Validation Failed")
			return err
		}
		p.Doc = &OpenApi{}
		p.Doc.SetDoc(doc)

	} else {
		var doc openapi2.T
		if err := utils.Read(filename, &doc, contentType); err != nil {
			return err
		}
		p.Doc = &Swagger{}
		p.Doc.SetDoc(&doc)
	}

	return nil
}
