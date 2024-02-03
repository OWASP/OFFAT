from sys import exc_info
from offat.api.models import CreateScanModel
from offat.tester.tester_utils import generate_and_run_tests
from offat.parsers import create_parser
from offat.logger import logger


def scan_api(body_data: CreateScanModel):
    try:
        api_parser = create_parser(fpath_or_url=None, spec=body_data.openAPI)

        results = generate_and_run_tests(
            api_parser=api_parser,
            regex_pattern=body_data.regex_pattern,
            req_headers=body_data.req_headers,
            rate_limit=body_data.rate_limit,
            test_data_config=body_data.test_data_config,
        )
        return results
    except Exception as e:
        logger.error('Error occurred while creating a job: %s', repr(e))
        logger.debug("Debug Data:", exc_info=exc_info())
        return [{'error': str(e)}]
