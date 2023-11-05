from asyncio import run
from copy import deepcopy
from re import search as regex_search

from .post_test_processor import PostRunTests
from .test_generator import TestGenerator
from .test_runner import TestRunner
from .test_results import TestResultTable
from ..report.generator import ReportGenerator
from ..logger import create_logger
from ..openapi import OpenAPIParser
from ..utils import write_json_to_file


logger = create_logger(__name__)

# create tester objs
test_table_generator = TestResultTable()
test_generator = TestGenerator()


def run_test(test_runner:TestRunner, tests:list[dict], regex_pattern:str=None, skip_test_run:bool=False, post_run_matcher_test:bool=False) -> list:
    '''Run tests and print result on console'''
    global test_table_generator
    # filter data if regex is passed
    if regex_pattern:
        tests = list(
            filter(
                lambda x: regex_search(regex_pattern, x.get('endpoint','')),
                tests 
            ) 
        )

    if skip_test_run:
        test_results = tests
    else:
        test_results = run(test_runner.run_tests(tests))

    if post_run_matcher_test:
        test_results = PostRunTests.matcher(test_results)

    # update test result for status based code filter
    test_results = PostRunTests.filter_status_code_based_results(test_results)
    
    # update tests result success/failure details
    test_results = PostRunTests.update_result_details(test_results)
    
    # run data leak tests
    test_results = PostRunTests.detect_data_exposure(test_results)

    # print results
    results = test_table_generator.generate_result_table(deepcopy(test_results))
    print(results)
    return test_results

 
# Note: redirects are allowed by default making it easier for pentesters/researchers
def generate_and_run_tests(api_parser:OpenAPIParser, regex_pattern:str=None, output_file:str=None, output_file_format:str=None, rate_limit:int=None,delay:float=None,req_headers:dict=None,proxy:str = None, ssl:bool = True, test_data_config:dict=None):
    global test_table_generator, logger

    test_runner = TestRunner(
        rate_limit=rate_limit,
        delay=delay,
        headers=req_headers,
        proxy=proxy,
        ssl=ssl,
    )
    
    results:list = []

    # test for unsupported http methods
    logger.info('Checking for Unsupported HTTP methods:')
    unsupported_http_endpoint_tests = test_generator.check_unsupported_http_methods(api_parser.base_url, api_parser._get_endpoints())
    results += run_test(test_runner=test_runner, tests=unsupported_http_endpoint_tests, regex_pattern=regex_pattern)

    # sqli fuzz test
    logger.info('Checking for SQLi vulnerability:')
    sqli_fuzz_tests = test_generator.sqli_fuzz_params_test(api_parser)
    results += run_test(test_runner=test_runner, tests=sqli_fuzz_tests, regex_pattern=regex_pattern)

    # OS Command Injection Fuzz Test
    logger.info('Checking for OS Command Injection Vulnerability with fuzzed params and checking response body:')
    os_command_injection_tests = test_generator.os_command_injection_fuzz_params_test(api_parser)
    results += run_test(test_runner=test_runner, tests=os_command_injection_tests, regex_pattern=regex_pattern, post_run_matcher_test=True)

    # XSS/HTML Injection Fuzz Test
    logger.info('Checking for XSS/HTML Injection Vulnerability with fuzzed params and checking response body:')
    os_command_injection_tests = test_generator.xss_html_injection_fuzz_params_test(api_parser)
    results += run_test(test_runner=test_runner, tests=os_command_injection_tests, regex_pattern=regex_pattern, post_run_matcher_test=True)
   
    # BOLA path tests with fuzzed data
    logger.info('Checking for BOLA in PATH using fuzzed params:')
    bola_fuzzed_path_tests = test_generator.bola_fuzz_path_test(api_parser, success_codes=[200, 201, 301])
    results += run_test(test_runner=test_runner, tests=bola_fuzzed_path_tests, regex_pattern=regex_pattern)

    # BOLA path test with fuzzed data + trailing slash
    logger.info('Checking for BOLA in PATH with trailing slash and id using fuzzed params:')
    bola_trailing_slash_path_tests = test_generator.bola_fuzz_trailing_slash_path_test(api_parser, success_codes=[200, 201, 301])
    results += run_test(test_runner=test_runner, tests=bola_trailing_slash_path_tests, regex_pattern=regex_pattern)

    # Mass Assignment / BOPLA 
    logger.info('Checking for Mass Assignment Vulnerability with fuzzed params and checking response status codes:')
    bopla_tests = test_generator.bopla_fuzz_test(api_parser, success_codes=[200, 201, 301])
    results += run_test(test_runner=test_runner, tests=bopla_tests, regex_pattern=regex_pattern)


    ## Tests with User provided Data
    if bool(test_data_config):
        logger.info('Testing with user provided data')

        # BOLA path tests with fuzzed + user provided data
        logger.info('Checking for BOLA in PATH using fuzzed and user provided params:')
        bola_fuzzed_user_data_tests = test_generator.test_with_user_data(
            test_data_config, 
            test_generator.bola_fuzz_path_test,
            openapi_parser=api_parser,
            success_codes=[200, 201, 301],
        )
        results += run_test(test_runner=test_runner, tests=bola_fuzzed_user_data_tests, regex_pattern=regex_pattern)

        # BOLA path test with fuzzed + user data + trailing slash
        logger.info('Checking for BOLA in PATH with trailing slash id using fuzzed and user provided params:')
        bola_trailing_slash_path_user_data_tests = test_generator.test_with_user_data(
            test_data_config,
            test_generator.bola_fuzz_trailing_slash_path_test,
            openapi_parser=api_parser,
            success_codes=[200, 201, 301],
        )
        results += run_test(test_runner=test_runner, tests=bola_trailing_slash_path_user_data_tests, regex_pattern=regex_pattern)

        # OS Command Injection Fuzz Test
        logger.info('Checking for OS Command Injection Vulnerability with fuzzed & user params and checking response body:')
        os_command_injection_with_user_data_tests = test_generator.test_with_user_data(
            test_data_config,
            test_generator.os_command_injection_fuzz_params_test,
            openapi_parser=api_parser,
        )
        results += run_test(test_runner=test_runner, tests=os_command_injection_with_user_data_tests, regex_pattern=regex_pattern, post_run_matcher_test=True)

        # XSS/HTML Injection Fuzz Test
        logger.info('Checking for XSS/HTML Injection Vulnerability with fuzzed & user params and checking response body:')
        os_command_injection_with_user_data_tests = test_generator.test_with_user_data(
            test_data_config,
            test_generator.xss_html_injection_fuzz_params_test,
            openapi_parser=api_parser,
        )
        results += run_test(test_runner=test_runner, tests=os_command_injection_with_user_data_tests, regex_pattern=regex_pattern, post_run_matcher_test=True)

        # Broken Access Control Test
        logger.info('Checking for Broken Access Control:')
        bac_results = PostRunTests.run_broken_access_control_tests(results, test_data_config)
        results += run_test(test_runner=test_runner, tests=bac_results, regex_pattern=regex_pattern, skip_test_run=True)
    

    # save file to output if output flag is present
    if output_file:
        ReportGenerator.generate_report(
            results=results,
            report_format=output_file_format,
            report_path=output_file,
        )

    return results