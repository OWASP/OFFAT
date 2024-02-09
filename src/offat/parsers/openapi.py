'''
module to parse OAS v3 documentation JSON/YAML files.
'''
from .parser import BaseParser
from ..logger import logger


class InvalidOpenAPIv3File(Exception):
    '''Exception to be raised when openAPI/OAS spec validation fails'''


class OpenAPIv3Parser(BaseParser):
    '''OpenAPI v3 Spec File Parser'''
    # while adding new method to this class, make sure same method is present in SwaggerParser class

    def __init__(self, file_or_url: str, spec: dict | None = None) -> None:
        super().__init__(file_or_url=file_or_url, spec=spec)  # noqa
        if not self.is_v3:
            raise InvalidOpenAPIv3File("Invalid OAS v3 file")

        self._populate_hosts()
        self.http_scheme = self._get_scheme()
        self.api_base_path = self.specification.get('basePath', '')
        self.base_url = f"{self.http_scheme}://{self.host}"

        self.request_response_params = self._get_request_response_params()

    def _populate_hosts(self):
        servers = self.specification.get('servers', [])
        hosts = []
        if not servers:
            logger.error('Invalid Server Url: Server URLs are missing in spec file')
            raise InvalidOpenAPIv3File('Server URLs Not Found in spec file')

        for server in servers:
            host = server.get('url', '').removeprefix(
                'https://').removeprefix('http://').removesuffix('/')
            host = None if host == '' else host
            hosts.append(host)

        self.hosts = hosts
        self.host = self.hosts[0]

    def _get_scheme(self):
        servers = self.specification.get('servers', [])
        schemes = []
        for server in servers:
            schemes.append('https' if 'https://' in server.get('url', '') else 'http')

        scheme = 'https' if 'https' in schemes else 'http'
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
                    'components', {}).get('schemas', {}).get(model_slug, {})  # model schema

        return param_schema

    def _get_response_definition_schema(self, responses: dict):
        '''returns schema of API response

        Args:
            responses (dict): responses from path http method json data

        Returns:
            dict:
        '''
        for status_code in responses.keys():
            # below line could return: ["application/json", "application/xml"]
            status_code_content_type_response = responses[status_code]['content'].keys()

            for status_code_content_type in status_code_content_type_response:
                status_code_content = responses[status_code]['content'][status_code_content_type].keys(
                )
                if 'parameters' in status_code_content:
                    # done
                    responses[status_code]['schema'] = responses[status_code]['content'][status_code_content_type]['parameters']
                elif 'schema' in status_code_content:
                    responses[status_code]['schema'] = self._get_param_definition_schema(
                        responses[status_code]['content'][status_code_content_type])

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

                request_parameters = paths[path][http_method].get(
                    'parameters', [])

                # create list of parameters: Fetch object schema from OAS file
                body_params = []

                body_parameter_keys = paths[path][http_method].get(
                    'requestBody', {}).get('content', {})

                for body_parameter_key in body_parameter_keys:
                    body_parameters_dict = paths[path][http_method]['requestBody']['content'][body_parameter_key]

                    required = paths[path][http_method]['requestBody'].get('required')
                    description = paths[path][http_method]['requestBody'].get('description')
                    body_param = self._get_param_definition_schema(body_parameters_dict)

                    body_params.append({
                        'in': 'body',
                        'name': body_parameter_key,
                        'description': description,
                        'required': required,
                        'schema': body_param,
                    })

                response_params = []
                response_params = self._get_response_definition_schema(
                    paths[path][http_method].get('responses', {}))

                # add body param to request param
                request_parameters += body_params
                requests.append({
                    'http_method': http_method,
                    'path': path,
                    'request_params': request_parameters,
                    'response_params': response_params,
                    'path_params': path_params,
                    'body_params': body_params,
                })

        return requests
