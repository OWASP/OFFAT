from aiohttp import ClientSession, ClientResponse
from os import name as os_name


import asyncio
import aiohttp.resolver

aiohttp.resolver.DefaultResolver = aiohttp.resolver.AsyncResolver
if os_name == 'nt':
    asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())

class AsyncRequests:
    '''
    AsyncRequests class helps to send HTTP requests.
    '''

    def __init__(self, headers: dict = None) -> None:
        '''AsyncRequests class constructor
        
        Args:
            headers (dict): overrides default headers while sending HTTP requests
        
        Returns:
            None
        '''
        self._headers = headers

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
        if not session:
            session = ClientSession(headers=self._headers)
            is_new_session = True

        method = str(method).upper()
        match method:
            case 'GET':
                sent_req = session.get(url, *args, **kwargs)
            case 'POST':
                sent_req = session.post(url, *args, **kwargs)
            case 'PUT':
                sent_req = session.put(url, *args, **kwargs)
            case 'PATCH':
                sent_req = session.patch(url, *args, **kwargs)
            case 'HEAD':
                sent_req = session.head(url, *args, **kwargs)
            case 'OPTIONS':
                sent_req = session.options(url, *args, **kwargs)
            case 'DELETE':
                sent_req = session.delete(url, *args, **kwargs)

        resp_data = None
        async with sent_req as response:
            resp_data = {
                        "status": response.status,
                        "req_url": str(response.request_info.real_url),
                        "query_url":str(response.url),
                        "req_method": response.request_info.method,
                        "req_headers": dict(**response.request_info.headers),
                        "res_redirection": str(response.history),
                        "res_headers": dict(response.headers),
                        "res_body": await response.text(),
                    }
        
            if is_new_session:
                await session.close()
                del session

        return resp_data


class AsyncRLRequests(AsyncRequests):
    '''
    Send Asynchronous rate limited HTTP requests.
    '''

    def __init__(self, rate_limit: int = 20, delay: float = 0.05, headers: dict = None) -> None:
        '''AsyncRLRequests constructor

        Args:
            rate_limit (int): number of concurrent requests at the same time
            delay (float): delay between consecutive requests
            headers (dict): overrides default headers while sending HTTP requests

        Returns:
            None
        '''
        assert isinstance(delay, float) or isinstance(delay, int)
        assert isinstance(rate_limit, float) or isinstance(rate_limit, int)

        self._delay = delay
        self._semaphore = asyncio.Semaphore(rate_limit)
        super().__init__(headers)

    async def request(self, url: str, method: str = 'GET', session: ClientSession = None, *args, **kwargs) -> ClientResponse:
        '''Send HTTP requests asynchronously with rate limit and delay between the requests

        Args:
            url (str): URL of the webpage/endpoint
            method (str): HTTP methods (default: GET) supports GET, POST, 
            PUT, HEAD, OPTIONS, DELETE
            session (aiohttp.ClientSession): aiohttp Client Session for sending requests
        
        Returns:
            dict: returns request and response data as dict
        '''
        async with self._semaphore:
            response = await super().request(url, method, session, *args, **kwargs)
            await asyncio.sleep(self._delay)
            return response
