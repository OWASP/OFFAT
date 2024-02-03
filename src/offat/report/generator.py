from copy import deepcopy
from html import escape
from json import dumps as json_dumps
from offat.report import templates
from os.path import dirname, join as path_join
from os import makedirs
from rich.table import Table
from yaml import dump as yaml_dump

from .templates.table import TestResultTable
from ..logger import logger, console


class ReportGenerator:
    @staticmethod
    def generate_html_report(results: list[dict]):
        html_report_template_file_name = 'report.html'
        html_report_file_path = path_join(
            dirname(templates.__file__), html_report_template_file_name)

        with open(html_report_file_path, 'r') as f:
            report_file_content = f.read()

        # TODO: validate report data to avoid HTML injection attacks.
        if not isinstance(results, list):
            raise ValueError('results arg expects a list[dict].')

        # HTML escape data
        escaped_results = []
        escape_keys = ["response_body"]
        for result_dict in results:
            escaped_result_dict = {}
            for key, value in result_dict.items():
                if key in escape_keys:
                    escaped_value = escape(value)
                    escaped_result_dict[key] = escaped_value
                else:
                    escaped_result_dict[key] = value

                escaped_results.append(escaped_result_dict)

        report_file_content = report_file_content.replace(
            '{ results }', json_dumps(escaped_results))

        return report_file_content

    @staticmethod
    def handle_report_format(results: list[dict], report_format: str | None) -> str | Table:
        result = None

        match report_format:
            case 'html':
                logger.warning('HTML output format displays only basic data.')
                result = ReportGenerator.generate_html_report(results=results)
            case 'yaml':
                logger.warning('YAML output format needs to be sanitized before using it further.')
                result = yaml_dump({
                    'results': results,
                })
            case 'json':
                report_format = 'json'
                result = json_dumps({
                    'results': results,
                })
            case _:  # default: CLI table
                # TODO: filter failed requests first and then create new table for failed requests
                report_format = 'table'
                results_table = TestResultTable().generate_result_table(
                    deepcopy(results))
                result = results_table

        logger.info('Generated %s format report.', report_format.upper())
        return result

    @staticmethod
    def save_report(report_path: str | None, report_file_content: str | Table | None):
        if report_path != '/' and report_path:
            dir_name = dirname(report_path)
            if dir_name != '' and report_path:
                makedirs(dir_name, exist_ok=True)

        # print to cli if report path and file content as absent else write to file location.
        if report_path and report_file_content and not isinstance(report_file_content, Table):
            with open(report_path, 'w') as f:
                logger.info('Writing report to file: %s', report_path)
                f.write(report_file_content)
        else:
            if isinstance(report_file_content, Table) and report_file_content.columns:
                TestResultTable().print_table(report_file_content)
            elif isinstance(report_file_content, Table) and not report_file_content.columns:
                logger.warning('No Columns found in Table.')
            else:
                console.print(report_file_content)

    @staticmethod
    def generate_report(results: list[dict], report_format: str | None, report_path: str | None):
        if report_path:
            report_format = report_path.split('.')[-1]

        formatted_results = ReportGenerator.handle_report_format(
            results=results, report_format=report_format)
        ReportGenerator.save_report(
            report_path=report_path, report_file_content=formatted_results)
