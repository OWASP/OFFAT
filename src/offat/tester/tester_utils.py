from asyncio import run
from http import client as http_client
from typing import Optional
from re import search as regex_search

from .post_test_processor import PostRunTests
from .test_generator import TestGenerator
from .test_runner import TestRunner
from ..report.generator import ReportGenerator
from ..logger import logger
from ..http import AsyncRequests
from ..openapi import OpenAPIParser


# create tester objs
test_generator = TestGenerator()


def is_host_up(openapi_parser: OpenAPIParser) -> bool:
    tokens = openapi_parser.host.split(":")
    match len(tokens):
        case 1:
            host = tokens[0]
            port = 443 if openapi_parser.http_scheme == "https" else 80
        case 2:
            host = tokens[0]
            port = tokens[1]
        case _:
            logger.warning(f"Invalid host: {openapi_parser.host}")
            return False

    logger.info(f"Checking whether host {host}:{port} is available")
    try:
        conn = http_client.HTTPConnection(host=host, port=port, timeout=5)
        conn.request("GET", "/")
        res = conn.getresponse()
        logger.info(f"Host returned status code: {res.status}")
        return res.status in range(200, 499)
    except Exception as e:
        logger.error(
            f"Unable to connect to host {host}:{port} due to error: {e}")
        return False


def run_test(test_runner: TestRunner, tests: list[dict], regex_pattern: Optional[str] = None, skip_test_run: Optional[bool] = False, post_run_matcher_test: Optional[bool] = False, description: Optional[str] = None) -> list:
    '''Run tests and print result on console'''
    # filter data if regex is passed
    if regex_pattern:
        tests = list(
            filter(
                lambda x: regex_search(regex_pattern, x.get('endpoint', '')),
                tests
            )
        )

    if skip_test_run:
        test_results = tests
    else:
        test_results = run(test_runner.run_tests(
            tests, description))

    if post_run_matcher_test:
        test_results = PostRunTests.matcher(test_results)

    # update test result for status based code filter
    test_results = PostRunTests.filter_status_code_based_results(test_results)

    # update tests result success/failure details
    test_results = PostRunTests.update_result_details(test_results)

    # run data leak tests
    test_results = PostRunTests.detect_data_exposure(test_results)

    return test_results


# Note: redirects are allowed by default making it easier for pentesters/researchers
def generate_and_run_tests(api_parser: OpenAPIParser, regex_pattern: Optional[str] = None, output_file: Optional[str] = None, output_file_format: Optional[str] = None, rate_limit: Optional[int] = None, delay: Optional[float] = None, req_headers: Optional[dict] = None, proxy: Optional[str] = None, ssl: Optional[bool] = True, test_data_config: Optional[dict] = None):
    global test_table_generator, logger

    if not is_host_up(openapi_parser=api_parser):
        logger.error(
            f"Stopping tests due to unavailibility of host: {api_parser.host}")
        return
    logger.info(f"Host {api_parser.host} is up")

    test_runner = TestRunner(
        rate_limit=rate_limit,
        headers=req_headers,
        proxy=proxy,
        ssl=ssl,
    )

    results: list = []

    # test for unsupported http methods
    test_name = 'Checking for Unsupported HTTP Methods/Verbs:'
    logger.info(test_name)
    unsupported_http_endpoint_tests = test_generator.check_unsupported_http_methods(
        api_parser)

    results += run_test(
        test_runner=test_runner,
        tests=unsupported_http_endpoint_tests,
        regex_pattern=regex_pattern,
        description='(FUZZED) ' + test_name
    )

    # sqli fuzz test
    test_name = 'Checking for SQLi vulnerability:'
    logger.info(test_name)
    sqli_fuzz_tests = test_generator.sqli_fuzz_params_test(api_parser)
    results += run_test(
        test_runner=test_runner,
        tests=sqli_fuzz_tests,
        regex_pattern=regex_pattern,
        description=f'(FUZZED) {test_name}',
    )

    test_name = 'Checking for SQLi vulnerability in URI Path:'
    logger.info(test_name)
    sqli_fuzz_tests = test_generator.sqli_in_uri_path_fuzz_test(api_parser)
    results += run_test(
        test_runner=test_runner,
        tests=sqli_fuzz_tests,
        regex_pattern=regex_pattern,
        description=f'(FUZZED) {test_name}',
    )

    # OS Command Injection Fuzz Test
    test_name = 'Checking for OS Command Injection Vulnerability with fuzzed params and checking response body:'
    logger.info(test_name)
    os_command_injection_tests = test_generator.os_command_injection_fuzz_params_test(
        api_parser)
    results += run_test(
        test_runner=test_runner,
        tests=os_command_injection_tests,
        regex_pattern=regex_pattern,
        post_run_matcher_test=True,
        description='(FUZZED) Checking for OS Command Injection:',
    )

    # XSS/HTML Injection Fuzz Test
    test_name = 'Checking for XSS/HTML Injection Vulnerability with fuzzed params and checking response body:'
    logger.info(test_name)
    os_command_injection_tests = test_generator.xss_html_injection_fuzz_params_test(
        api_parser)
    results += run_test(
        test_runner=test_runner,
        tests=os_command_injection_tests,
        regex_pattern=regex_pattern,
        post_run_matcher_test=True,
        description='(FUZZED) Checking for XSS/HTML Injection:',
    )

    # BOLA path tests with fuzzed data
    test_name = 'Checking for BOLA in PATH using fuzzed params:'
    logger.info(test_name)
    bola_fuzzed_path_tests = test_generator.bola_fuzz_path_test(
        api_parser, success_codes=[200, 201, 301])
    results += run_test(
        test_runner=test_runner,
        tests=bola_fuzzed_path_tests,
        regex_pattern=regex_pattern,
        description='(FUZZED) Checking for BOLA in PATH:'
    )

    # BOLA path test with fuzzed data + trailing slash
    test_name = 'Checking for BOLA in PATH with trailing slash and id using fuzzed params:'
    logger.info(test_name)
    bola_trailing_slash_path_tests = test_generator.bola_fuzz_trailing_slash_path_test(
        api_parser, success_codes=[200, 201, 301])
    results += run_test(
        test_runner=test_runner,
        tests=bola_trailing_slash_path_tests,
        regex_pattern=regex_pattern,
        description='(FUZZED) Checking for BOLA in PATH with trailing slash:'
    )

    # Mass Assignment / BOPLA
    test_name = 'Checking for Mass Assignment Vulnerability with fuzzed params and checking response status codes:'
    logger.info(test_name)
    bopla_tests = test_generator.bopla_fuzz_test(
        api_parser, success_codes=[200, 201, 301])
    results += run_test(
        test_runner=test_runner,
        tests=bopla_tests,
        regex_pattern=regex_pattern,
        description='(FUZZED) Checking for Mass Assignment Vulnerability:',
    )

    # Tests with User provided Data
    if bool(test_data_config):
        logger.info('[bold]Testing with user provided data[/bold]')

        # BOLA path tests with fuzzed + user provided data
        test_name = 'Checking for BOLA in PATH using fuzzed and user provided params:',
        logger.info(test_name)
        bola_fuzzed_user_data_tests = test_generator.test_with_user_data(
            test_data_config,
            test_generator.bola_fuzz_path_test,
            openapi_parser=api_parser,
            success_codes=[200, 201, 301],
        )
        results += run_test(
            test_runner=test_runner,
            tests=bola_fuzzed_user_data_tests,
            regex_pattern=regex_pattern,
            description='(USER + FUZZED) Checking for BOLA in PATH:',
        )

        # BOLA path test with fuzzed + user data + trailing slash
        test_name = 'Checking for BOLA in PATH with trailing slash id using fuzzed and user provided params:'
        logger.info(test_name)
        bola_trailing_slash_path_user_data_tests = test_generator.test_with_user_data(
            test_data_config,
            test_generator.bola_fuzz_trailing_slash_path_test,
            openapi_parser=api_parser,
            success_codes=[200, 201, 301],
        )
        results += run_test(
            test_runner=test_runner,
            tests=bola_trailing_slash_path_user_data_tests,
            regex_pattern=regex_pattern,
            description='(USER + FUZZED) Checking for BOLA in PATH with trailing slash:',
        )

        # OS Command Injection Fuzz Test
        test_name = 'Checking for OS Command Injection Vulnerability with fuzzed & user params and checking response body:'
        logger.info(test_name)
        os_command_injection_with_user_data_tests = test_generator.test_with_user_data(
            test_data_config,
            test_generator.os_command_injection_fuzz_params_test,
            openapi_parser=api_parser,
        )
        results += run_test(
            test_runner=test_runner,
            tests=os_command_injection_with_user_data_tests,
            regex_pattern=regex_pattern,
            post_run_matcher_test=True,
            description='(USER + FUZZED) Checking for OS Command Injection Vulnerability:',
        )

        # XSS/HTML Injection Fuzz Test
        test_name = 'Checking for XSS/HTML Injection Vulnerability with fuzzed & user params and checking response body:'
        logger.info(test_name)
        os_command_injection_with_user_data_tests = test_generator.test_with_user_data(
            test_data_config,
            test_generator.xss_html_injection_fuzz_params_test,
            openapi_parser=api_parser,
        )
        results += run_test(
            test_runner=test_runner,
            tests=os_command_injection_with_user_data_tests,
            regex_pattern=regex_pattern,
            post_run_matcher_test=True,
            description='(USER + FUZZED) Checking for XSS/HTML Injection:',
        )

        # Broken Access Control Test
        test_name = 'Checking for Broken Access Control:'
        logger.info(test_name)
        bac_results = PostRunTests.run_broken_access_control_tests(
            results, test_data_config)
        results += run_test(
            test_runner=test_runner,
            tests=bac_results,
            regex_pattern=regex_pattern,
            skip_test_run=True,
            description=test_name,
        )

    # save file to output if output flag is present
    if output_file_format != 'table':
        ReportGenerator.generate_report(
            results=results,
            report_format=output_file_format,
            report_path=output_file,
        )

    ReportGenerator.generate_report(
        results=results,
        report_format='table',
        report_path=None,
    )

    return results
