package logging

import (
	"os"

	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"github.com/rs/zerolog/pkgerrors"
)

func init() {
	// setup logging
	zerolog.TimeFieldFormat = zerolog.TimeFormatUnix
	zerolog.ErrorStackMarshaler = pkgerrors.MarshalStack

	writer := zerolog.ConsoleWriter{
		Out:     os.Stderr,
		NoColor: false,
	}

	log.Logger = log.With().Caller().Logger().Output(writer)

}
