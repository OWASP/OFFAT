package parser

import (
	"fmt"
	"os"

	"github.com/OWASP/OFFAT/src/pkg/http"
	_ "github.com/OWASP/OFFAT/src/pkg/logging"
	"github.com/OWASP/OFFAT/src/pkg/utils"

	c "github.com/dmdhrumilmistry/fasthttpclient/client"

	"github.com/getkin/kin-openapi/openapi2"
	"github.com/getkin/kin-openapi/openapi3"
	"github.com/rs/zerolog/log"
)

type Parser struct {
	Version string
	BaseUrl string

	IsOpenApi             bool // else Swagger
	IsExternalRefsAllowed bool

	// OAS validation opts
	DisableExamplesValidation       bool
	DisableSchemaDefaultsValidation bool
	DisableSchemaPatternValidation  bool

	// Parsed Docs
	Doc DocInterface
}

func NewParser(isExternalRefsAllowed, disableExamplesValidation, disableSchemaDefaultsValidation, disableSchemaPatternValidation bool) *Parser {
	return &Parser{
		DisableExamplesValidation:       disableExamplesValidation,
		DisableSchemaDefaultsValidation: disableSchemaDefaultsValidation,
		DisableSchemaPatternValidation:  disableSchemaPatternValidation,
		IsExternalRefsAllowed:           isExternalRefsAllowed,
	}
}

// Parses and Populates file contents to Parser struct fields.
// Note: URLs only support JSON content for now.
func (p *Parser) Parse(filename string, isUrl bool) (err error) {
	var contentType string
	var content []byte
	var head struct {
		OpenAPI string `json:"openapi" yaml:"openapi"`
		Swagger string `json:"swagger" yaml:"swagger"`
	}

	// get documentation content
	if isUrl {
		// make call to doc url
		resp, err := c.Get(http.DefaultClient.Client, filename, nil, nil) // this request won't be proxied
		if err != nil {
			log.Error().Stack().Err(err).Msg("Failed to fetch API documentation from url")
			return err
		}

		if resp.StatusCode == 200 {
			content = resp.Body
		} else {
			return fmt.Errorf("unable to fetch api doc from %s server returned %d status code", filename, resp.StatusCode)
		}

	} else {
		// read file content
		_, err = os.Stat(filename)
		if err != nil {
			log.Error().Err(err).Msg("file not found")
			return err
		}

		content, err = os.ReadFile(filename)
		if err != nil {
			return err
		}
	}

	// get content type of file/url
	contentType, err = utils.DetectContentType(content)
	if err != nil {
		log.Error().Stack().Err(err).Msg("Failed to load API Documentation due to invalid content type!")
		return err
	}

	// parse file from its specific content type
	if err := utils.LoadJsonYaml(content, &head, contentType); err != nil {
		log.Error().Stack().Err(err).Msgf("Failed to load API documentation from url file content with %s content type", contentType)
		return err
	}

	// infer file type: OAS/Swagger
	if head.OpenAPI != "" {
		p.Version = head.OpenAPI
		p.IsOpenApi = true
	} else if head.Swagger != "" {
		p.Version = head.Swagger
	} else {
		err = fmt.Errorf("invalid OAS/swagger version")
		log.Error().Stack().Err(err)
		return err
	}

	// Parse documentation
	if p.IsOpenApi {
		loader := openapi3.NewLoader()
		loader.IsExternalRefsAllowed = p.IsExternalRefsAllowed

		// Load data from file
		doc, err := loader.LoadFromData(content)
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
		if err := utils.LoadJsonYaml(content, &doc, contentType); err != nil {
			return err
		}
		p.Doc = &Swagger{}
		p.Doc.SetDoc(&doc)
	}

	return nil
}

func (p *Parser) FuzzDocHttpParams() {
	// TODO: handle and return error
	p.Doc.FuzzDocHttpParams()
}
