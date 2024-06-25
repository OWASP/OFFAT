from sys import exc_info
from offat.utils import is_valid_url
from offat.api.schema import CreateScanSchema
from offat.tester.handler import generate_and_run_tests
from offat.parsers import create_parser
from offat.logger import logger


def scan_api(body_data: CreateScanSchema, ssl_verify: bool = True):
    try:
        url = body_data.openapi if is_valid_url(body_data.openapi) else None
        spec = None if url else body_data.openapi

        api_parser = create_parser(fpath_or_url=url, spec=spec, ssl_verify=ssl_verify)

        results = generate_and_run_tests(
            api_parser=api_parser,
            regex_pattern=body_data.regex_pattern,
            req_headers=body_data.req_headers,
            rate_limit=body_data.rate_limit,
            test_data_config=body_data.test_data_config,
            proxies=body_data.proxies,
            capture_failed=body_data.capture_failed,
            remove_unused_data=body_data.remove_unused_data,
        )
        return results
    except Exception as e:
        logger.error('Error occurred while creating a job: %s', repr(e))
        logger.error('Debug Data:', exc_info=exc_info())
        return [{'error': str(e)}]
