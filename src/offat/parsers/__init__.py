from requests import get as http_get
from yaml import safe_load as yaml_load, YAMLError
from .openapi import OpenAPIv3Parser
from .swagger import SwaggerParser
from .parser import BaseParser
from ..utils import is_valid_url
from ..logger import logger


def create_parser(
    fpath_or_url: str,
    spec: dict | None = None,
    server_url: str | None = None,
    ssl_verify: bool = True,
) -> SwaggerParser | OpenAPIv3Parser:
    """returns parser based on doc file"""
    if fpath_or_url and is_valid_url(fpath_or_url):
        res = http_get(fpath_or_url, timeout=3, verify=ssl_verify)
        if res.status_code != 200:
            logger.error(
                'server returned status code %d offat expects 200 status code',
                res.status_code,
            )
            exit(-1)

        # A spec served over a url can be JSON or YAML, same as a local file.
        # JSON is a subset of YAML, so safe_load handles both.
        try:
            spec = yaml_load(res.text)
        except YAMLError:
            logger.error('Failed to parse spec fetched from url as JSON/YAML')
            exit(-1)

        if not isinstance(spec, dict):
            logger.error('Spec fetched from url is not a valid JSON/YAML object')
            exit(-1)

        fpath_or_url = None  # type: ignore

    try:
        parser = BaseParser(file_or_url=fpath_or_url, spec=spec, server_url=server_url)
    except OSError:
        logger.error('File Not Found')
        exit(-1)

    if parser.is_v3:
        return OpenAPIv3Parser(
            file_or_url=fpath_or_url, spec=spec, server_url=server_url
        )

    return SwaggerParser(fpath_or_url=fpath_or_url, spec=spec, server_url=server_url)
