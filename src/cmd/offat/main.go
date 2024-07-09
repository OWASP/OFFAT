package main

import (
	"flag"
	"log"

	"github.com/OWASP/OFFAT/src/pkg/openapi"
)

type Config struct {
	Filename *string
}

func main() {
	config := Config{}

	config.Filename = flag.String("f", "", "OAS/Swagger Doc file path")
	flag.Parse()

	parser := openapi.Parser{}
	parser.Parse(*config.Filename)
	log.Println(*config.Filename)
	log.Println(parser.Version)
}
