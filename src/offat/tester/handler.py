"""
module to handle the test generation and running of tests
"""
from .generator import TestGenerator
from .tester_utils import run_test, is_host_up, reduce_data_list
from .post_test_processor import PostRunTests
from .runner import TestRunner
from ..parsers.openapi import OpenAPIv3Parser
from ..parsers.swagger import SwaggerParser
from ..report.generator import ReportGenerator
from ..report.summary import ResultSummarizer
from ..logger import logger, console

# create tester obj
test_generator = TestGenerator()


# Note: redirects are allowed by default making it easier for pentesters/researchers
def generate_and_run_tests(
    api_parser: SwaggerParser | OpenAPIv3Parser,
    regex_pattern: str | None = None,
    output_file: str | None = None,
    output_file_format: str | None = None,
    rate_limit: int | None = None,
    req_headers: dict | None = None,
    proxies: list[str] | None = None,
    test_data_config: dict | None = None,
    capture_failed: bool = False,
    remove_unused_data: bool = True,
):
    """
    Generates and runs tests for the provided OAS/Swagger file.

    Args:
        api_parser: An instance of SwaggerParser or OpenAPIv3Parser
        representing the parsed API specification.
        regex_pattern: A string representing the regex pattern to
        match against the response body (optional).
        output_file: A string representing the path to the output
        file (optional).
        output_file_format: A string representing the format of the
        output file (optional).
        rate_limit: An integer representing the rate limit for the
        tests (optional).
        req_headers: A dictionary representing the request headers
        (optional).
        proxies: A list of strings representing the proxies to be used
        (optional).
        test_data_config: A dictionary representing the configuration
        for user-provided test data (optional).
        capture_failed: A boolean indicating whether to capture failed
        tests in the report (default: False).
        remove_unused_data: A boolean indicating whether to remove
        unused data (default: True).

    Returns:
        A list of test results.
    """
    if not is_host_up(openapi_parser=api_parser):
        logger.error(
            'Stopping tests due to unavailability of host: %s', api_parser.host
        )
        return

    logger.info('Host %s is up', api_parser.host)

    test_runner = TestRunner(
        rate_limit=rate_limit,
        headers=req_headers,
        proxies=proxies,
    )

    results: list = []

    test_list = []

    # test for unsupported http methods
    test_list.append(
        {
            'test_name': 'Checking for Unsupported HTTP Methods/Verbs',
            'tests': test_generator.check_unsupported_http_methods(api_parser),
            'type': 'FUZZED',
        }
    )

    # sqli fuzz test
    test_list.append(
        {
            'test_name': 'Checking for SQLi vulnerability',
            'tests': test_generator.sqli_fuzz_params_test(api_parser),
            'type': 'FUZZED',
        }
    )

    test_list.append(
        {
            'test_name': 'Checking for SQLi vulnerability in URI Path',
            'tests': test_generator.sqli_in_uri_path_fuzz_test(api_parser),
            'type': 'FUZZED',
        }
    )

    # OS Command Injection Fuzz Test
    test_list.append(
        {
            'test_name': 'Checking for OS Command Injection Vulnerability with fuzzed params and checking response body',  # noqa: E501
            'tests': test_generator.os_command_injection_fuzz_params_test(api_parser),
            'type': 'FUZZED',
            'post_run_matcher_test': True,
        }
    )

    # XSS/HTML Injection Fuzz Test
    test_list.append(
        {
            'test_name': 'Checking for XSS/HTML Injection Vulnerability with fuzzed params and checking response body',  # noqa: E501
            'tests': test_generator.xss_html_injection_fuzz_params_test(api_parser),
            'type': 'FUZZED',
            'post_run_matcher_test': True,
        }
    )

    # BOLA path tests with fuzzed data
    test_list.append(
        {
            'test_name': 'Checking for BOLA in PATH using fuzzed params',
            'tests': test_generator.bola_fuzz_path_test(
                api_parser, success_codes=[200, 201, 301]
            ),
            'type': 'FUZZED',
        }
    )

    # BOLA path test with fuzzed data + trailing slash
    test_list.append(
        {
            'test_name': 'Checking for BOLA in PATH with trailing slash and id using fuzzed params',
            'tests': test_generator.bola_fuzz_trailing_slash_path_test(
                api_parser, success_codes=[200, 201, 301]
            ),
            'type': 'FUZZED',
        }
    )

    # Mass Assignment / BOPLA
    test_list.append(
        {
            'test_name': 'Checking for Mass Assignment Vulnerability with fuzzed params and checking response status codes:',  # noqa: E501
            'tests': test_generator.bopla_fuzz_test(
                api_parser, success_codes=[200, 201, 301]
            ),
            'type': 'FUZZED',
        }
    )

    # SSTI Vulnerability
    test_list.append(
        {
            'test_name': 'Checking for SSTI vulnerability with fuzzed params and checking response body',  # noqa: E501
            'tests': test_generator.ssti_fuzz_params_test(api_parser),
            'type': 'FUZZED',
            'post_run_matcher_test': True,
        }
    )

    # Missing Authorization Test
    test_list.append(
        {
            'test_name': 'Checking for Missing Authorization',
            'tests': test_generator.missing_auth_fuzz_test(api_parser),
            'type': 'FUZZED',
        }
    )

    # Tests with User provided Data
    if bool(test_data_config):
        logger.info('[bold] Testing with user provided data [/bold]')

        # BOLA path tests with fuzzed + user provided data
        test_list.append(
            {
                'test_name': 'Checking for BOLA in PATH using fuzzed and user provided params',
                'tests': test_generator.test_with_user_data(
                    test_data_config,
                    test_generator.bola_fuzz_path_test,
                    openapi_parser=api_parser,
                    success_codes=[200, 201, 301],
                ),
                'type': 'USER + FUZZED',
            }
        )

        # BOLA path test with fuzzed + user data + trailing slash
        test_list.append(
            {
                'test_name': 'Checking for BOLA in PATH with trailing slash id using fuzzed and user provided params:',  # noqa: E501
                'tests': test_generator.test_with_user_data(
                    test_data_config,
                    test_generator.bola_fuzz_trailing_slash_path_test,
                    openapi_parser=api_parser,
                    success_codes=[200, 201, 301],
                ),
                'type': 'USER + FUZZED',
            }
        )

        # OS Command Injection Fuzz Test
        test_list.append(
            {
                'test_name': 'Checking for OS Command Injection Vulnerability with fuzzed & user params and checking response body',  # noqa: E501
                'tests': test_generator.test_with_user_data(
                    test_data_config,
                    test_generator.os_command_injection_fuzz_params_test,
                    openapi_parser=api_parser,
                ),
                'type': 'USER + FUZZED',
                'post_run_matcher_test': True,
            }
        )

        # XSS/HTML Injection Fuzz Test
        test_list.append(
            {
                'test_name': 'Checking for XSS/HTML Injection Vulnerability with fuzzed & user params and checking response body',  # noqa: E501
                'tests': test_generator.test_with_user_data(
                    test_data_config,
                    test_generator.xss_html_injection_fuzz_params_test,
                    openapi_parser=api_parser,
                ),
                'type': 'USER + FUZZED',
                'post_run_matcher_test': True,
            }
        )

        # STTI Vulnerability
        test_list.append(
            {
                'test_name': 'Checking for SSTI vulnerability with fuzzed params & user data and checking response body',  # noqa: E501
                'tests': test_generator.test_with_user_data(
                    test_data_config,
                    test_generator.ssti_fuzz_params_test,
                    openapi_parser=api_parser,
                ),
                'type': 'USER + FUZZED',
                'post_run_matcher_test': True,
            }
        )

        # Missing Authorization Test
        test_list.append(
            {
                'test_name': 'Checking for Missing Authorization with user data',
                'tests': test_generator.test_with_user_data(
                    test_data_config,
                    test_generator.missing_auth_fuzz_test,
                    openapi_parser=api_parser,
                ),
                'type': 'USER + FUZZED',
                'post_run_matcher_test': True,
            }
        )

    for test in test_list:
        if 'post_run_matcher_test' not in test:
            test['post_run_matcher_test'] = False

        logger.info(test['test_name'])

        results += run_test(
            test_runner=test_runner,
            tests=test['tests'],
            regex_pattern=regex_pattern,
            post_run_matcher_test=test['post_run_matcher_test'],
            description=f'({test["type"]}) {test["test_name"]}',
        )

    # After we collected all the results, we can now test them for
    #  access without restrictions
    if bool(test_data_config):
        # Broken Access Control Test
        test_name = 'Checking for Broken Access Control'
        logger.info(test_name)
        bac_results = PostRunTests.run_broken_access_control_tests(
            results, test_data_config
        )

        results += run_test(
            test_runner=test_runner,
            tests=bac_results,
            regex_pattern=regex_pattern,
            skip_test_run=True,
            description=test_name,
        )

    if remove_unused_data:
        for result in results:
            result.pop('kwargs', None)
            result.pop('args', None)

            result['body_params'] = reduce_data_list(result.get('body_params', [{}]))
            result['query_params'] = reduce_data_list(result.get('query_params', [{}]))
            result['path_params'] = reduce_data_list(result.get('path_params', [{}]))
            result['malicious_payload'] = reduce_data_list(
                result.get('malicious_payload', [])
            )

    # save file to output if output flag is present
    if output_file_format != 'table':
        ReportGenerator.generate_report(
            results=results,
            report_format=output_file_format,
            report_path=output_file,
            capture_failed=capture_failed,
        )

    ReportGenerator.generate_report(
        results=results,
        report_format='table',
        report_path=None,
        capture_failed=capture_failed,
    )

    console.print(
        "The columns for 'data_leak' and 'vulnerable' in the table represent independent aspects. It's possible for there to be a data leak in the endpoint, yet the result for that endpoint may still be marked as 'Success'. This is because the 'vulnerable' column doesn't necessarily reflect the overall test result; it may indicate success even in the presence of a data leak."
    )

    console.rule()
    result_summary = ResultSummarizer.generate_count_summary(
        results, table_title='Results Summary'
    )

    console.print(result_summary)

    return results
