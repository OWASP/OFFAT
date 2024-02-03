from copy import deepcopy
from .logger import logger


def validate_config_file_data(test_config_data: dict):
    if not isinstance(test_config_data, dict):
        logger.warning('Invalid data format')
        return False

    if test_config_data.get('error', False):
        logger.warning('Error Occurred While reading file: %s', test_config_data)
        return False

    if not test_config_data.get('actors', ):
        logger.warning('actors are required')
        return False

    if not test_config_data.get('actors', [])[0].get('actor1', None):
        logger.warning('actor1 is required')
        return False

    logger.info('User provided data will be used for generating test cases')
    return test_config_data


def populate_user_data(actor_data: dict, actor_name: str, tests: list[dict]):
    tests = deepcopy(tests)
    headers = actor_data.get('request_headers', [])
    body_params = actor_data.get('body', [])
    query_params = actor_data.get('query', [])
    path_params = actor_data.get('path', [])

    # create HTTP request headers
    request_headers = {}
    for header in headers:
        request_headers[header.get('name')] = header.get('value')

    for test in tests:
        #  replace key and value instead of appending
        test['body_params'] += body_params
        test['query_params'] += query_params
        test['path_params'] += path_params
        # for post test processing tests such as broken authentication
        test['test_actor_name'] = actor_name
        if test.get('kwargs', {}).get('headers', {}).items():
            test['kwargs']['headers'] = dict(
                test['kwargs']['headers'], **request_headers)
        else:
            test['kwargs']['headers'] = request_headers

    return tests
