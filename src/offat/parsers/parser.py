from openapi_spec_validator import validate
from openapi_spec_validator.readers import read_from_filename
from ..logger import logger


class InvalidSpecVersion(Exception):
    '''Exception to be raised '''
    pass


class BaseParser:
    def __init__(self, file_or_url: str, spec: dict = None) -> None:
        if spec:
            self.specification = spec
            base_uri = ""
        else:
            self.specification, base_uri = read_from_filename(file_or_url)

        try:
            validate(spec=self.specification, base_uri=base_uri)
            self.valid = True
        except Exception as e:
            logger.warning("OAS/Swagger file is invalid!")
            logger.error('Failed to validate spec %s due to err: %s', file_or_url, repr(e))
            self.valid = False

        self.is_v3 = self._get_oas_version() == 3

        self.hosts = []

    def _get_oas_version(self):
        if self.specification.get('openapi'):
            return 3
        elif self.specification.get('swagger'):
            return 2
        raise InvalidSpecVersion("only openapi and swagger specs are supported for now")

    def _get_endpoints(self):
        '''Returns list of endpoint paths along with HTTP methods allowed'''
        endpoints = []

        for endpoint in self.specification.get('paths', {}).keys():
            methods = list(self.specification['paths'][endpoint].keys())
            if 'parameters' in methods:
                methods.remove('parameters')
            endpoints.append((endpoint, methods))

        return endpoints

    def _get_endpoint_details_for_fuzz_test(self):
        return self.specification.get('paths')
