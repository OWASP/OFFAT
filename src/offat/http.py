from aiohttp import ClientSession, ClientResponse, TCPConnector
from os import name as os_name
from typing import Optional


import asyncio
import aiohttp.resolver

aiohttp.resolver.DefaultResolver = aiohttp.resolver.AsyncResolver
if os_name == 'nt':
    asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())


class AsyncRequests:
    '''
    AsyncRequests class helps to send HTTP requests with rate limiting options.
    '''

    def __init__(self, rate_limit: Optional[int] = None, delay: Optional[float] = None, headers: Optional[dict] = None, proxy: Optional[str] = None, ssl: Optional[bool] = True, allow_redirects: Optional[bool] = True) -> None:
        '''AsyncRequests class constructor

        Args:
            rate_limit (int): number of concurrent requests at the same time
            delay (float): delay between consecutive requests
            headers (dict): overrides default headers while sending HTTP requests
            proxy (str): proxy URL to be used while sending requests
            ssl (bool): ignores few SSL errors if value is False

        Returns:
            None
        '''
        self._rate_limit = rate_limit
        self._delay = delay
        self._headers = headers
        self._proxy = proxy if proxy else None
        self._ssl = ssl if ssl else None
        self._allow_redirects = allow_redirects

    async def request(self, url: str, method: str = 'GET', session: ClientSession = None, *args, **kwargs) -> ClientResponse:
        '''Send HTTP requests asynchronously

        Args:
            url (str): URL of the webpage/endpoint
            method (str): HTTP methods (default: GET) supports GET, POST, 
            PUT, HEAD, OPTIONS, DELETE
            session (aiohttp.ClientSession): aiohttp Client Session for sending requests


        Returns:
            dict: returns request and response data as dict
        '''
        is_new_session = False
        connector = TCPConnector(ssl=self._ssl, limit=self._rate_limit,)

        if not session:
            session = ClientSession(headers=self._headers, connector=connector)
            is_new_session = True

        method = str(method).upper()
        match method:
            case 'GET':
                sent_req = session.get(
                    url, proxy=self._proxy, allow_redirects=self._allow_redirects, *args, **kwargs)
            case 'POST':
                sent_req = session.post(
                    url, proxy=self._proxy, allow_redirects=self._allow_redirects, *args, **kwargs)
            case 'PUT':
                sent_req = session.put(
                    url, proxy=self._proxy, allow_redirects=self._allow_redirects, *args, **kwargs)
            case 'PATCH':
                sent_req = session.patch(
                    url, proxy=self._proxy, allow_redirects=self._allow_redirects, *args, **kwargs)
            case 'HEAD':
                sent_req = session.head(
                    url, proxy=self._proxy, allow_redirects=self._allow_redirects, *args, **kwargs)
            case 'OPTIONS':
                sent_req = session.options(
                    url, proxy=self._proxy, allow_redirects=self._allow_redirects, *args, **kwargs)
            case 'DELETE':
                sent_req = session.delete(
                    url, proxy=self._proxy, allow_redirects=self._allow_redirects, *args, **kwargs)

        resp_data = None
        async with sent_req as response:
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

            if is_new_session:
                await session.close()
                del session

        if self._delay:
            await asyncio.sleep(self._delay)

        return resp_data
