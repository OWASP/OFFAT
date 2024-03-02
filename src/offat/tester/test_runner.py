from asyncio import ensure_future, gather
from asyncio.exceptions import CancelledError
from enum import Enum
from sys import exc_info, exit
from rich.progress import Progress, TaskID


from ..http import AsyncRequests
from ..logger import logger, console


class PayloadFor(Enum):
    BODY = 0
    QUERY = 1


class TestRunner:
    def __init__(self, rate_limit: float = 60, headers: dict | None = None, proxy: str | None = None) -> None:
        self._client = AsyncRequests(
            rate_limit=rate_limit, headers=headers, proxy=proxy)
        self.progress = Progress(console=console)
        self.progress_task_id: TaskID | None = None

    def _generate_payloads(self, params: list[dict], payload_for: PayloadFor = PayloadFor.BODY):
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
            raise ValueError(
                '`payload_for` arg only supports `PayloadFor.BODY, PayloadFor.QUERY` value')

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
        args = test_task.get('args')
        kwargs = test_task.get('kwargs')
        body_params = test_task.get('body_params')
        query_params = test_task.get('query_params')

        if body_params and str(http_method).upper() not in ['GET', 'OPTIONS']:
            kwargs['json'] = self._generate_payloads(
                body_params, payload_for=PayloadFor.BODY)

        if query_params:
            kwargs['params'] = self._generate_payloads(
                query_params, payload_for=PayloadFor.QUERY)

        test_result = test_task
        try:
            response = await self._client.request(url=url, method=http_method, *args, **kwargs)
            # add request headers to result
            test_result['request_headers'] = response.get('req_headers', [])
            # append response headers and body for analyzing data leak
            res_body = response.get('res_body', 'No Response Body Found')
            test_result['response_headers'] = response.get('res_headers')
            test_result['response_body'] = res_body
            test_result['response_status_code'] = response.get('status')
            test_result['redirection'] = response.get('res_redirection', '')
            test_result['error'] = False

        except Exception as e:
            test_result['request_headers'] = []
            test_result['response_headers'] = []
            test_result['response_body'] = 'No Response Body Found'
            test_result['response_status_code'] = -1
            test_result['redirection'] = ''
            test_result['error'] = True

            logger.debug('Exception Debug Data:', exc_info=exc_info())
            logger.error('Unable to send request due to error: %s', e)
            logger.error(locals())

        # advance progress bar
        if self.progress_task_id:
            self.progress.update(self.progress_task_id, advance=1, refresh=True)

        if self.progress and self.progress.finished:
            self.progress.stop()
            self.progress_task_id = None

        return test_result

    async def run_tests(self, test_tasks: list, description: str | None):
        '''run tests generated from test generator module'''
        self.progress.start()
        self.progress_task_id = self.progress.add_task(
            f'[orange] {description}', total=len(test_tasks))
        tasks = []

        for test_task in test_tasks:
            tasks.append(ensure_future(self.send_request(test_task)))

        try:
            results = await gather(*tasks)
            return results

        except (KeyboardInterrupt, CancelledError,):
            logger.error("[!] User Interruption Detected!")
            exit(-1)

        except Exception as e:
            logger.error("[*] Exception occurred while gathering results: %s",
                         e, exc_info=exc_info())
            return []
