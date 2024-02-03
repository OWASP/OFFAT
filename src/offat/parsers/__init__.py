from .openapi import OpenAPIv3Parser
from .swagger import SwaggerParser
from .parser import BaseParser


def create_parser(fpath_or_url: str) -> SwaggerParser | OpenAPIv3Parser:
    '''returns parser based on doc file'''
    parser = BaseParser(file_or_url=fpath_or_url)
    if parser.is_v3:
        return OpenAPIv3Parser(file_or_url=fpath_or_url)

    return SwaggerParser(fpath_or_url=fpath_or_url)
