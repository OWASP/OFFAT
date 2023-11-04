from asyncio import ensure_future, gather
from aiohttp.client_exceptions import ClientProxyConnectionError
from enum import Enum
from traceback import print_exc
from ..http import AsyncRequests
from ..logger import create_logger

logger = create_logger(__name__)


# TODO: move filters to post processing module
class TestRunnerFiltersEnum(Enum):
    STATUS_CODE_FILTER = 0
    BODY_REGEX_FILTER = 1
    HEADER_REGEX_FILTER = 2

class PayloadFor(Enum):
    BODY = 0
    QUERY = 1


class TestRunner:
    def __init__(self, rate_limit:int=None, delay:float=None, headers:dict=None, proxy: str = None, ssl: bool = True) -> None:
        self._client = AsyncRequests(rate_limit=rate_limit, delay=delay, headers=headers, proxy=proxy, ssl=ssl)


    def _generate_payloads(self, params:list[dict], payload_for:PayloadFor=PayloadFor.BODY):
        '''Generate body payload from passed data for HTTP body and query.
        
        Args:
            params (list[dict]): list of containing payload parameters
            payload_for (PayloadFor): PayloadFor constant indicating 
            for which payload is be generated, default: `PayloadFor.BODY`

        Returns:
            dict: dictionary containing payload as key value pairs generated from params.

        Raises:
            ValueError: If incorrect `payload_for` argument is not of `PayloadFor` class.
        '''
        if payload_for not in [PayloadFor.BODY, PayloadFor.QUERY]:
            raise ValueError('`payload_for` arg only supports `PayloadFor.BODY, PayloadFor.QUERY` value')

        body_payload = {}
        query_payload = {}

        for param in params:
            param_in = param.get('in')
            param_name = param.get('name')
            param_value = param.get('value')

            # TODO:handle schema

            match param_in:
                case 'body':
                    body_payload[param_name] = param_value
                case 'query':
                    query_payload[param_name] = param_value
                case _:
                    continue
        
        match payload_for:
            case PayloadFor.BODY:
                return body_payload
            
            case PayloadFor.QUERY:
                return query_payload
            
        return {}
    

    async def send_request(self, test_task):
        url = test_task.get('url')
        http_method = test_task.get('method')
        success_codes = test_task.get('success_codes', [200, 301])
        args = test_task.get('args')
        kwargs = test_task.get('kwargs')
        body_params = test_task.get('body_params')
        query_params = test_task.get('query_params')

        if body_params and str(http_method).upper() not in ['GET', 'OPTIONS']:
            kwargs['json'] = self._generate_payloads(body_params, payload_for=PayloadFor.BODY)

        if query_params:
            kwargs['params'] = self._generate_payloads(query_params, payload_for=PayloadFor.QUERY)

        try:
            response = await self._client.request(url=url, method=http_method, *args, **kwargs)
        except ConnectionRefusedError:
            logger.error('Connection Failed! Server refused Connection!!')
        except ClientProxyConnectionError as e:
            logger.error(f'Proxy Connection Error: {e}')

        test_result = test_task

        # add request headers to result
        test_result['request_headers'] = response.get('req_headers',[])
        # append response headers and body for analyzing data leak
        res_body = response.get('res_body', 'No Response Body Found')
        test_result['response_headers'] = response.get('res_headers')
        test_result['response_body'] = res_body
        test_result['response_status_code'] = response.get('status')
        test_result['redirection'] = response.get('res_redirection', '')

        return test_result


    async def run_tests(self, test_tasks:list):
        '''run tests generated from test generator module'''
        tasks = []

        for test_task in test_tasks:
            tasks.append(
                ensure_future(
                    self.send_request(test_task)
                )
            )

        try:
            results = await gather(*tasks)
            return results
        except Exception as e:
            print(f'[*] Exception occurred while gathering results: {e}')
            print_exc()
            return []