from rich.table import Table, Column
from ...logger import console


class TestResultTable:
    def __init__(
        self,
        table_width_percentage: float = 98,
    ) -> None:
        self.console = console
        self.table_width_percentage = table_width_percentage

    def print_table(self, table: Table):
        terminal_width = console.width
        table_width = int(terminal_width * (self.table_width_percentage / 100))
        table.width = table_width

        self.console.print(table)
        self.console.rule()

    def extract_result_table_cols(self, results: list[dict]) -> list[str]:
        return sorted({key for dictionary in results for key in dictionary.keys()})

    def generate_result_cols(self, results_list: list[dict]) -> list[Column]:
        return [
            Column(header=col_header, overflow='fold')
            for col_header in self.extract_result_table_cols(results_list)
        ]

    def generate_result_table(self, results: list, filter_passed_results: bool = True):
        results = self._sanitize_results(results, filter_passed_results)
        cols = self.generate_result_cols(results)
        table = Table(*cols)

        for result in results:
            table_row = []
            for col in cols:
                table_row.append(str(result.get(col.header, '[red]:bug: - [/red]')))
            table.add_row(*table_row)

        return table

    def _sanitize_results(
        self,
        results: list,
        filter_passed_results: bool = True,
        is_leaking_data: bool = False,
    ):
        if filter_passed_results:
            results = list(
                filter(
                    lambda result: result.get('vulnerable') or result.get('data_leak'),
                    results,
                )
            )

        keys_to_remove = [
            'url',
            'test_name',
            'response_filter',
            'body_params',
            'request_headers',
            'redirection',
            'query_params',
            'path_params',
            'curl_command',
            'response_match_regex',
            'regex_match_result',
            'success_codes',
        ]

        # remove keys based on conditions or update their values
        for result in results:
            if result['vulnerable']:
                result['vulnerable'] = '[bold red]True \u00d7[/bold red]'
            else:
                result['vulnerable'] = '[bold green]False \u2713[/bold green]'

            if not is_leaking_data:
                del result['response_headers']
                del result['response_body']

            if result.get('response_status_code'):
                result['status_code'] = result.get('response_status_code')
                del result['response_status_code']

            if result.get('security') or result.get('security') == []:
                del result['security']

            if result.get('data_leak'):
                result['data_leak'] = '[bold red]Leak Found \u00d7[/bold red]'
            else:
                result['data_leak'] = '[bold green]No Leak \u2713[/bold green]'

            if not isinstance(result.get('malicious_payload'), str):
                del result['malicious_payload']

            for key in keys_to_remove:
                if key in result:
                    del result[key]

        return results
