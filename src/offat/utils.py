from json import loads as json_load, dumps as json_dumps, JSONDecodeError
from pkg_resources import get_distribution
from os.path import isfile
from yaml import safe_load, YAMLError
from .logger import logger


def get_package_version():
    '''Returns package current version

    Args:
        None

    Returns:
        String: current package version
    '''
    return get_distribution('offat').version


def read_yaml(file_path: str) -> dict:
    '''Reads YAML file and returns as python dict. 
    returns file not found or yaml errors as dict.

    Args:
        file_path (str): path of yaml file

    Returns:
        dict: YAML contents as dict else returns error 
    '''
    if not file_path:
        return {"error": "ValueError, path cannot be of None type"}

    if not isfile(file_path):
        return {"error": "File Not Found"}

    with open(file_path) as f:
        try:
            return safe_load(f.read())
        except YAMLError:
            return {"error": "YAML error"}


def read_json(file_path: str) -> dict:
    '''Reads JSON file and returns as python dict. 
    returns file not found or JSON errors as dict.

    Args:
        file_path (str): path of yaml file

    Returns:
        dict: YAML contents as dict else returns error 
    '''
    if not isfile(file_path):
        return {"error": "File Not Found"}

    with open(file_path) as f:
        try:
            return json_load(f.read())
        except JSONDecodeError:
            return {"error": "JSON error"}


def read_openapi_file(file_path: str) -> dict:
    '''Returns Open API Documentation file contents as json
    returns file not found or yaml errors as dict.

    Args:
        file_path (str): path of openapi file

    Returns:
        dict: YAML contents as dict else returns error 
    '''
    if not isfile(file_path):
        return {"error": "File Not Found"}

    file_ext = file_path.split('.')[-1]
    match file_ext:
        case 'json':
            return read_json(file_path)
        case 'yaml':
            return read_yaml(file_path)
        case _:
            return {"error": "Invalid file extension"}


def write_json_to_file(json_data: dict, file_path: str):
    '''Writes dict obj to file as json

    Args:
        json_data (dict): JSON payload to be written into file
        file_path (str): path of output json file

    Returns:
        bool: True is `json_data` is written into `file_path` else
        returns False (in case of any exception) 

    Raises:
        Any exception occurred during operation
    '''
    if isfile(file_path):
        logger.info(f'{file_path} file will be overwritten.')

    logger.info(f'Writing data to file: {file_path}')
    try:
        with open(file_path, 'w') as f:
            f.write(json_dumps(json_data))
            logger.info(f'Completed writing data to file: {file_path}')
            return True

    except JSONDecodeError:
        logger.error(
            f'Invalid JSON data, error while writing to {file_path} file.')

    except Exception as e:
        logger.error(
            f'Unable to write JSON data to file due to below exception:\n{repr(e)}')

    return False


def str_to_dict(key_values: str) -> dict:
    '''Takes string object and converts to dict 
    String should in `Key1:Value1,Key2:Value2,Key3:Value3` format

    Args:
        key_values (str): dict as str separated by commas `,`

    Returns:
        dict: Returns dict from str after conversion

    Raises:
        Any exception occurred during operation
    '''
    new_dict = dict()
    for key_value in key_values.split(','):
        try:
            key_value_list = key_value.split(':')
            key = key_value_list[0].strip()
            value = key_value_list[1].strip()
            new_dict[key] = value
        except (IndexError, KeyError) as e:
            logger.error(str(e))

    return new_dict


def headers_list_to_dict(headers_list_list: list[list[str]]) -> dict | None:
    '''Takes list object and converts to dict 
    String should in `[['Key1:Value1'],['Key2:Value2'],['Key3:Value3']]` format

    Args:
        headers_list_list (list): headers value as list[list[str]], where str 
        is in `key:value` format

    Returns:
        dict: Returns dict from str after conversion

    Raises:
        Any exception occurred during operation
    '''
    if not headers_list_list:
        return None

    response_headers_dict: dict = dict()

    for header_list in headers_list_list:
        for header_data in header_list:
            header_key_value = header_data.split(':')
            k = header_key_value[0].strip()
            v = header_key_value[1].strip()
            response_headers_dict[k] = v

    return response_headers_dict
