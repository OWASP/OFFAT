from traceback import print_exception
from offat.api.models import CreateScanModel
from offat.tester.tester_utils import generate_and_run_tests
from offat.openapi import OpenAPIParser
from offat.logger import logger


def scan_api(body_data: CreateScanModel):
    try:
        logger.info('test')
        api_parser = OpenAPIParser(fpath_or_url=None, spec=body_data.openAPI)

        results = generate_and_run_tests(
            api_parser=api_parser,
            regex_pattern=body_data.regex_pattern,
            req_headers=body_data.req_headers,
            rate_limit=body_data.rate_limit,
            delay=body_data.delay,
            test_data_config=body_data.test_data_config,
        )
        return results
    except Exception as e:
        logger.error(f'Error occurred while creating a job: {e}')
        print_exception(e)
        return [{'error': str(e)}]
