'''
module to parse Swagger v2 documentation JSON/YAML files.
'''
from .parser import BaseParser
from ..logger import logger


class InvalidSwaggerFile(Exception):
    '''Exception to be raised when swagger spec validation fails'''


class SwaggerParser(BaseParser):
    '''Swagger Spec file Parser'''
    # while adding new method to this class, make sure same method is present in OpenAPIv3Parser class

    def __init__(self, fpath_or_url: str, spec: dict | None = None) -> None:
        super().__init__(file_or_url=fpath_or_url, spec=spec)  # noqa
        if self.is_v3:
            raise InvalidSwaggerFile("Invalid OAS v3 file")

        self._populate_hosts()
        self.http_scheme = self._get_scheme()
        self.api_base_path = self.specification.get('basePath', '')
        self.base_url = f"{self.http_scheme}://{self.host}"
        self.request_response_params = self._get_request_response_params()

    def _populate_hosts(self):
        host = self.specification.get('host')
        if not host:
            logger.error('Invalid Host: Host is missing')
            raise InvalidSwaggerFile('Host Not Found in spec file')
        hosts = [host]
        self.hosts = hosts
        self.host = self.hosts[0]

    def _get_scheme(self):
        scheme = 'https' if 'https' in self.specification.get('schemes', []) else 'http'
        return scheme

    def _get_param_definition_schema(self, param: dict):
        '''Returns Model defined schema for the passed param'''
        param_schema = param.get('schema')

        # replace schema $ref with model params
        if param_schema:
            param_schema_ref = param_schema.get('$ref')

            if param_schema_ref:
                model_slug = param_schema_ref.split('/')[-1]
                param_schema = self.specification.get(
                    'definitions', {}).get(model_slug)

        return param_schema

    def _get_response_definition_schema(self, responses: dict):
        '''returns schema of API response

        Args:
            responses (dict): responses from path http method json data

        Returns:
            dict:
        '''
        for status_code in responses.keys():
            status_code_response = responses[status_code].keys()
            if 'parameters' in status_code_response:
                responses[status_code]['schema'] = responses[status_code]['parameters']
            elif 'schema' in status_code_response:
                responses[status_code]['schema'] = self._get_param_definition_schema(
                    responses[status_code])
            else:
                continue

        return responses

    def _get_request_response_params(self):
        '''Returns Schema of requests and response params

        Args:
            None

        Returns:
            list:
        '''
        requests = []
        paths = self.specification.get('paths', {})

        # extract endpoints and supported params
        for path in paths.keys():
            path_params = paths[path].get('parameters', [])

            for http_method in paths.get(path, {}).keys():
                # consider only http methods
                if http_method not in ['get', 'put', 'post', 'delete', 'options']:
                    continue

                # below var contains overall params
                request_parameters = paths[path][http_method].get(
                    'parameters', [])
                response_params = self._get_response_definition_schema(
                    paths[path][http_method].get('responses', {}))

                # create list of parameters: Fetch object schema from OAS file
                for param in request_parameters:
                    param['schema'] = self._get_param_definition_schema(param)

                requests.append({
                    'http_method': http_method,
                    'path': path,
                    'request_params': request_parameters,
                    'response_params': response_params,
                    'path_params': path_params,
                })

        return requests
