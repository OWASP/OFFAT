from offat.report import templates
from os.path import dirname, join as path_join
from os import makedirs
from yaml import dump as yaml_dump
from json import dumps as json_dumps

from ..logger import create_logger


logger = create_logger(__name__)


class ReportGenerator:
    @staticmethod
    def generate_html_report(results:list[dict]):
        html_report_template_file_name = 'report.html'
        html_report_file_path = path_join(dirname(templates.__file__),html_report_template_file_name)

        with open(html_report_file_path, 'r') as f:
            report_file_content = f.read()

        # TODO: validate report path to avoid injection attacks.
        if not isinstance(results, list):
            raise ValueError('results arg expects a list[dict].')
        
        report_file_content = report_file_content.replace('{ results }', json_dumps(results))

        return report_file_content
        
    @staticmethod
    def handle_report_format(results:list[dict], report_format:str) -> str:
        result = None

        match report_format:
            case 'html':
                logger.warning('HTML output format displays only basic data.')
                result = ReportGenerator.generate_html_report(results=results)
            case 'yaml':
                logger.warning('YAML output format needs to be sanitized before using it further.')
                result = yaml_dump({
                    'results':results,
                })
            case _: # default json format
                report_format = 'json'
                result = json_dumps({
                    'results':results,
                })
        
        logger.info(f'Generated {report_format.upper()} format report.')
        return result


    @staticmethod
    def save_report(report_path:str, report_file_content:str):
        if report_path != '/':
            dir_name = dirname(report_path)
            makedirs(dir_name, exist_ok=True)

        with open(report_path, 'w') as f:
            logger.info(f'Writing report to file: {report_path}')
            f.write(report_file_content)


    @staticmethod
    def generate_report(results:list[dict], report_format:str, report_path:str):
        formatted_results = ReportGenerator.handle_report_format(results=results, report_format=report_format)
        ReportGenerator.save_report(report_path=report_path, report_file_content=formatted_results)
