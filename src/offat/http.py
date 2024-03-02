from os import name as os_name
from aiohttp import ClientSession, ClientTimeout
from aiolimiter import AsyncLimiter
from tenacity import retry, stop_after_attempt, retry_if_not_exception_type

import asyncio
import aiohttp.resolver

aiohttp.resolver.DefaultResolver = aiohttp.resolver.AsyncResolver
if os_name == 'nt':
    asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())


class AsyncRequests:
    '''
    AsyncRequests class helps to send HTTP requests with rate limiting options.
    '''

    def __init__(self, rate_limit: float = 50, headers: dict | None = None, proxy: str | None = None, allow_redirects: bool = True, timeout: float = 60) -> None:
        '''AsyncRequests class constructor

        Args:
            rate_limit (int): number of requests per seconds
            delay (float): delay between consecutive requests
            headers (dict): overrides default headers while sending HTTP requests
            proxy (str): proxy URL to be used while sending requests
            timeout (float): total timeout parameter of aiohttp.ClientTimeout

        Returns:
            None
        '''
        self._headers = headers
        self._proxy = proxy if proxy else None
        self._allow_redirects = allow_redirects
        self._limiter = AsyncLimiter(max_rate=rate_limit, time_period=1)
        self._timeout = ClientTimeout(total=timeout)

    @retry(stop=stop_after_attempt(3), retry=retry_if_not_exception_type(KeyboardInterrupt or asyncio.exceptions.CancelledError))
    async def request(self, url: str, method: str = 'GET', *args, **kwargs) -> dict:
        '''Send HTTP requests asynchronously

        Args:
            url (str): URL of the webpage/endpoint
            method (str): HTTP methods (default: GET) supports GET, POST, 
            PUT, HEAD, OPTIONS, DELETE

        Returns:
            dict: returns request and response data as dict
        '''
        async with self._limiter:
            async with ClientSession(headers=self._headers, timeout=self._timeout) as session:
                method = str(method).upper()
                match method:
                    case 'GET':
                        req_method = session.get
                    case 'POST':
                        req_method = session.post
                    case 'PUT':
                        req_method = session.put
                    case 'PATCH':
                        req_method = session.patch
                    case 'HEAD':
                        req_method = session.head
                    case 'OPTIONS':
                        req_method = session.options
                    case 'DELETE':
                        req_method = session.delete
                    case _:
                        req_method = session.get

                async with req_method(url, proxy=self._proxy, allow_redirects=self._allow_redirects, *args, **kwargs) as response:
                    resp_data = {
                        "status": response.status,
                        "req_url": str(response.request_info.real_url),
                        "query_url": str(response.url),
                        "req_method": response.request_info.method,
                        "req_headers": dict(**response.request_info.headers),
                        "res_redirection": str(response.history),
                        "res_headers": dict(response.headers),
                        "res_body": await response.text(),
                    }

                return resp_data
