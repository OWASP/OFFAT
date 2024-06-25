from argparse import ArgumentParser

from .parsers.openapi import OpenAPIv3Parser
from .parsers.swagger import SwaggerParser
from .config_data_handler import validate_config_file_data
from .tester.handler import generate_and_run_tests
from .parsers import create_parser
from .utils import get_package_version, headers_list_to_dict, read_yaml


def banner():
    """Prints OWASP OFFAT cli banner"""
    print(
        r"""
      _/|       |\_
     /  |       |  \
    |    \     /    |
    |  \ /     \ /  |
    | \  |     |  / |
    | \ _\_/^\_/_ / |
    |    --\//--    |
     \_  \     /  _/
       \__  |  __/
          \ _ /
         _/   \_
        / _/|\_ \
         /  |  \
          / v \
          OFFAT
    """
    )


def start():
    """Starts cli tool"""
    banner()

    parser = ArgumentParser(prog='offat')
    parser.add_argument(
        '-f',
        '--file',
        dest='fpath',
        type=str,
        help='path or url of openapi/swagger specification file',
        required=True,
    )
    parser.add_argument(
        '-v', '--version', action='version', version=f"%(prog)s {get_package_version()}"
    )
    parser.add_argument(
        '-rl',
        '--rate-limit',
        dest='rate_limit',
        help='API requests rate limit per second',
        type=float,
        default=60,
        required=False,
    )
    parser.add_argument(
        '-pr',
        '--path-regex',
        dest='path_regex_pattern',
        type=str,
        help='run tests for paths matching given regex pattern',
        required=False,
        default=None,
    )
    parser.add_argument(
        '-o',
        '--output',
        dest='output_file',
        type=str,
        help='path to store test results',
        required=False,
        default=None,
    )
    parser.add_argument(
        '-of',
        '--format',
        dest='output_format',
        type=str,
        choices=['json', 'yaml', 'html', 'table'],
        help='Data format to save (json, yaml, html, table). Default: table',
        required=False,
        default='table',
    )
    parser.add_argument(
        '-H',
        '--headers',
        dest='headers',
        type=str,
        help='HTTP requests headers that should be sent during testing eg: User-Agent: offat',
        required=False,
        default=None,
        action='append',
        nargs='*',
    )
    parser.add_argument(
        '-tdc',
        '--test-data-config',
        dest='test_data_config',
        help='YAML file containing user test data for tests',
        required=False,
        type=str,
    )
    parser.add_argument(
        '-p',
        '--proxy',
        dest='proxies_list',
        help='Proxy server URL to route HTTP requests through (e.g. "http://proxyserver:port")',
        action='append',
        required=False,
        type=str,
        default=None,
    )
    parser.add_argument(
        '-s',
        '--ssl-verify',
        dest='ssl_verify',
        required=False,
        action='store_true',
        help='Enable SSL Verification',
    )
    parser.add_argument(
        '-cf',
        '--capture-failed',
        dest='capture_failed',
        action='store_true',
        help='Captures failed requests due to any exceptions into output file',
    )
    parser.add_argument(
        '--server',
        dest='server_url',
        type=str,
        default=None,
        required=False,
        help='server/host base url to overwrite from OAS/Swagger file',
    )
    args = parser.parse_args()

    # convert req headers str to dict
    headers_dict: dict = headers_list_to_dict(args.headers)

    # handle rate limiting options
    # TODO: allow user to opt out of rate limit
    rate_limit = args.rate_limit

    # handle test user data config file
    test_data_config = args.test_data_config
    if test_data_config:
        test_data_config = read_yaml(args.test_data_config)
        test_data_config = validate_config_file_data(test_data_config)

    # parse args and run tests
    api_parser: SwaggerParser | OpenAPIv3Parser = create_parser(
        args.fpath, server_url=args.server_url,
        ssl_verify=args.ssl_verify
    )

    generate_and_run_tests(
        api_parser=api_parser,
        regex_pattern=args.path_regex_pattern,
        output_file=args.output_file,
        output_file_format=args.output_format,
        req_headers=headers_dict,
        rate_limit=rate_limit,
        test_data_config=test_data_config,
        proxies=args.proxies_list,
        capture_failed=args.capture_failed,
    )


if __name__ == '__main__':
    start()
