from offat.report import templates
from os.path import dirname, join as path_join
from json import dumps


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
        
        report_file_content = report_file_content.replace('{ results }', dumps(results))

        return report_file_content
        


    @staticmethod
    def save_report(report_path:str, report_file_content:str):
        with open(report_path, 'w') as f:
            f.write(report_file_content)
