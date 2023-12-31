from prance import ResolvingParser
from .logger import logger


class OpenAPIParser:
    ''''''

    def __init__(self, fpath_or_url: str, spec: dict = None) -> None:
        self._parser = ResolvingParser(
            fpath_or_url, backend='openapi-spec-validator', spec_string=spec)

        if self._parser.valid:
            logger.info('Specification file is valid')
        else:
            logger.error('Specification file is invalid!')

        self._spec = self._parser.specification

        self.hosts = []
        self._populate_hosts()
        self.host = self.hosts[0]

        self.http_scheme = 'https' if 'https' in self._spec.get(
            'schemes', []) else 'http'
        self.api_base_path = self._spec.get('basePath', '')
        self.base_url = f"{self.http_scheme}://{self.host}"
        self.request_response_params = self._get_request_response_params()

    def _populate_hosts(self):
        if self._spec.get('openapi'):  # for openapi v3
            servers = self._spec.get('servers', [])
            hosts = []
            for server in servers:
                host = server.get('url', '').removeprefix(
                    'http://').removeprefix('http://').removesuffix('/')
                host = None if host == '' else host
                hosts.append(host)
        else:
            host = self._spec.get('host')  # for swagger files
            if not host:
                logger.error('Invalid Host: Host is missing')
                raise ValueError('Host Not Found in spec file')
            hosts = [host]

        self.hosts = hosts

    def _get_endpoints(self):
        '''Returns list of endpoint paths along with HTTP methods allowed'''
        endpoints = []

        for endpoint in self._spec.get('paths', {}).keys():
            methods = list(self._spec['paths'][endpoint].keys())
            if 'parameters' in methods:
                methods.remove('parameters')
            endpoints.append((endpoint, methods))

        return endpoints

    def _get_endpoint_details_for_fuzz_test(self):
        return self._spec.get('paths')

    def _get_param_definition_schema(self, param: dict):
        '''Returns Model defined schema for the passed param'''
        param_schema = param.get('schema')

        # replace schema $ref with model params
        if param_schema:
            param_schema_ref = param_schema.get('$ref')

            if param_schema_ref:
                model_slug = param_schema_ref.split('/')[-1]
                param_schema = self._spec.get(
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
        paths = self._spec.get('paths', {})

        # extract endpoints and supported params
        for path in paths.keys():
            path_params = paths[path].get('parameters', [])

            for http_method in paths.get(path, {}).keys():
                # consider only http methods
                if http_method not in ['get', 'put', 'post', 'delete', 'options']:
                    continue

                body_parameters = paths[path][http_method].get(
                    'parameters', [])
                response_params = self._get_response_definition_schema(
                    paths[path][http_method].get('responses', {}))

                # create list of parameters
                for param in body_parameters:
                    param['schema'] = self._get_param_definition_schema(param)

                requests.append({
                    'http_method': http_method,
                    'path': path,
                    'request_params': body_parameters,
                    'response_params': response_params,
                    'path_params': path_params,
                })

        return requests
