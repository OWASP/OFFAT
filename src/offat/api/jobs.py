from ..tester.tester_utils import generate_and_run_tests
from ..openapi import OpenAPIParser


def scan_api(open_api:dict):
    # TODO: validate `open_api` str against openapi specs. 
    api_parser = OpenAPIParser(fpath=None,spec=open_api)

    # TODO: accept commented options from API
    results = generate_and_run_tests(
        api_parser=api_parser,
        # regex_pattern=args.path_regex_pattern,
        # output_file=args.output_file,
        # req_headers=headers_dict,
        # rate_limit=rate_limit,
        # delay=delay_rate,
        # test_data_config=test_data_config,
    )
    return results
