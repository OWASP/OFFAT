"""
OWASP OFFAT Tester Utils Module
"""
from http import client as http_client
import ssl
from sys import exc_info
from typing import Optional
from asyncio import run
from asyncio.exceptions import CancelledError
from re import search as regex_search


from .post_test_processor import PostRunTests
from .runner import TestRunner
from ..logger import logger
from ..parsers import SwaggerParser, OpenAPIv3Parser


def is_host_up(openapi_parser: SwaggerParser | OpenAPIv3Parser, ssl_verify: bool = True) -> bool:
    '''checks whether the host from openapi doc is available or not.
    Returns True is host is available else returns False'''
    tokens = openapi_parser.host.split(':')
    use_ssl = False
    match len(tokens):
        case 1:
            host = tokens[0]
            port = 443 if openapi_parser.http_scheme == 'https' else 80
        case 2:
            host = tokens[0]
            port = int(tokens[1])
        case _:
            logger.warning('Invalid host: %s', openapi_parser.host)
            return False

    host = host.split('/')[0]

    match port:
        case 443:
            use_ssl = True
            proto = http_client.HTTPSConnection
        case _:
            proto = http_client.HTTPConnection

    logger.info('Checking whether host %s:%s is available', host, port)
    try:
        if not use_ssl:
            conn = proto(host=host, port=port, timeout=5)
        else:
            if ssl_verify:
                conn = proto(host=host, port=port, timeout=5)
            else:
                conn = proto(
                    host=host,
                    port=port,
                    timeout=5,
                    context = ssl._create_unverified_context())
        conn.request('GET', '/')
        res = conn.getresponse()
        logger.info('Host returned status code: %d', res.status)
        return res.status in range(200, 499)
    except Exception as e:
        logger.error(
            'Unable to connect to host %s:%s due to error: %s', host, port, repr(e)
        )
        return False


def run_test(
    test_runner: TestRunner,
    tests: list[dict],
    regex_pattern: Optional[str] = None,
    skip_test_run: Optional[bool] = False,
    post_run_matcher_test: Optional[bool] = False,
    description: Optional[str] = None,
) -> list:
    '''Run tests and print result on console'''
    logger.info('Tests Generated: %d', len(tests))

    # filter data if regex is passed
    if regex_pattern:
        tests = list(
            filter(lambda x: regex_search(regex_pattern, x.get('endpoint', '')), tests)
        )

    try:
        if skip_test_run:
            logger.warning('Skipping test run for: %s', description)
            test_results = tests
        else:
            test_results = run(test_runner.run_tests(tests, description))

    except (
        KeyboardInterrupt,
        CancelledError,
    ):
        logger.error('[!] User Interruption Detected!')
        exit(-1)

    except Exception as e:
        logger.error(
            '[*] Exception occurred while running tests: %s', e, exc_info=exc_info()
        )
        return []

    if post_run_matcher_test:
        test_results = PostRunTests.matcher(test_results)
    else:
        # update test result for status based code filter
        test_results = PostRunTests.filter_status_code_based_results(test_results)

    # update tests result success/failure details
    test_results = PostRunTests.update_result_details(test_results)

    # run data leak tests
    test_results = PostRunTests.detect_data_exposure(test_results)

    return test_results


def reduce_data_list(data_list: list[dict] | str) -> list[dict] | str:
    """
    Reduces a list of dictionaries to only include 'name' and 'value' keys.

    Args:
        data_list (list[dict] | str): The input data list to be reduced.

    Returns:
        list[dict] | str: The reduced data list with only 'name' and 'value' keys.

    """
    if isinstance(data_list, list):
        return [
            {'name': param.get('name'), 'value': param.get('value')}
            for param in data_list
        ]

    return data_list
