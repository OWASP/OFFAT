"""
module for interacting with HTTP layer
"""
from random import choice
from os import name as os_name
from urllib.parse import urlparse

from aiohttp import ClientSession, ClientTimeout
from aiolimiter import AsyncLimiter
from tenacity import retry, stop_after_attempt, retry_if_not_exception_type

import asyncio
import aiohttp.resolver

aiohttp.resolver.DefaultResolver = aiohttp.resolver.AsyncResolver
if os_name == "nt":
    asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())


class Proxies:
    """
    class for handling proxies
    """

    def __init__(self, proxies: list[str] | None) -> None:
        self.p_list = proxies

    def validate_proxy(self, proxy_url: str | None):
        """
        Validates a proxy URL based on format and attempts a basic connection.

        Args:
            proxy_url: The URL of the proxy server.

        Returns:
            True if the proxy URL seems valid and a basic connection can be established, False otherwise.
        """
        # Check for valid URL format
        # TODO: implement url parse security: https://docs.python.org/3/library/urllib.parse.html#url-parsing-security
        parsed_url = urlparse(proxy_url)
        if all([parsed_url.scheme, parsed_url.netloc]):
            return True

        return False

    def get_random_proxy(self) -> str | None:
        """
        Returns random proxy from the list
        """
        if not self.p_list:
            return None
        return choice(self.p_list)


class AsyncRequests:
    """
    AsyncRequests class helps to send HTTP requests with rate limiting options.
    """

    def __init__(
        self,
        rate_limit: float = 50,
        headers: dict | None = None,
        proxies: list[str] | None = [],
        allow_redirects: bool = True,
        timeout: float = 60,
        ssl_verify: bool = True,
    ) -> None:
        """AsyncRequests class constructor

        Args:
            rate_limit (int): number of requests per seconds
            delay (float): delay between consecutive requests
            headers (dict): overrides default headers while sending HTTP requests
            proxy (str): proxy URL to be used while sending requests
            timeout (float): total timeout parameter of aiohttp.ClientTimeout
            ssl_verify (bool): enforces tls/ssl verification if True

        Returns:
            None
        """
        self._headers = headers
        self._proxy = Proxies(proxies=proxies)
        self._allow_redirects = allow_redirects
        self._limiter = AsyncLimiter(max_rate=rate_limit, time_period=1)
        self._timeout = ClientTimeout(total=timeout)
        self._ssl_verify = ssl_verify

    @retry(
        stop=stop_after_attempt(3),
        retry=retry_if_not_exception_type(
            KeyboardInterrupt or asyncio.exceptions.CancelledError
        ),
    )
    async def request(self, url: str, *args, method: str = "GET", **kwargs) -> dict:
        """Send HTTP requests asynchronously

        Args:
            url (str): URL of the webpage/endpoint
            method (str): HTTP methods (default: GET) supports GET, POST,
            PUT, HEAD, OPTIONS, DELETE

        Returns:
            dict: returns request and response data as dict
        """
        async with self._limiter:
            async with ClientSession(
                headers=self._headers, timeout=self._timeout
            ) as session:
                method = str(method).upper()
                match method:
                    case "GET":
                        req_method = session.get
                    case "POST":
                        req_method = session.post
                    case "PUT":
                        req_method = session.put
                    case "PATCH":
                        req_method = session.patch
                    case "HEAD":
                        req_method = session.head
                    case "OPTIONS":
                        req_method = session.options
                    case "DELETE":
                        req_method = session.delete
                    case _:
                        req_method = session.get

                async with req_method(
                    url,
                    allow_redirects=self._allow_redirects,
                    proxy=self._proxy.get_random_proxy(),
                    ssl=self._ssl_verify,
                    *args,
                    **kwargs,
                ) as response:
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
