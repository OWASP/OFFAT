"""
OWASP OFFAT summarizer class module
"""
from rich.table import Table, Column


class ResultSummarizer:
    """class for summarizing results"""

    @staticmethod
    def get_counts(results: list[dict], filter_errors: bool = False) -> dict[str, int]:
        """
        Processes results and returns test summary of errored, succeeded, failed
        and data leak endpoint results count.

        Args:
            results (list): OFFAT results list of dict
            filter_errors (bool): filters errored results before processing count
            if True. Default value: False

        Returns:
            dict: name (str) as key and its associated count (int)
        """
        if filter_errors:
            results = list(filter(lambda result: result.get('error', False), results))

        error_count = 0
        data_leak_count = 0
        immune_count = 0
        vulnerable_count = 0
        for result in results:
            error_count += 1 if result.get('error', False) else 0
            data_leak_count += 1 if result.get('data_leak', False) else 0

            if result.get('vulnerable'):
                vulnerable_count += 1
            else:
                immune_count += 1

        count_dict = {
            'errors': error_count,
            'data_leaks': data_leak_count,
            'immune': immune_count,
            'vulnerable': vulnerable_count,
        }

        return count_dict

    @staticmethod
    def generate_count_summary(
        results: list[dict],
        filter_errors: bool = False,
        output_format: str = 'table',
        table_title: str | None = None,
    ) -> Table | str:
        """
        Processes results and returns test summary of errored, succeeded, failed
        and data leak endpoint results count.

        Args:
            results (list): OFFAT results list of dict
            filter_errors (bool): filters errored results before processing count
            if True. Default value: False
            output_format (str): expected output format (table, markdown)

        Returns:
            rich.Table | str : returns summary in expected format
        """
        count_summary = ResultSummarizer.get_counts(
            results=results, filter_errors=filter_errors
        )
        match output_format:
            case 'markdown':
                output = ''
                if table_title:
                    output += f"**{table_title}**\n"

                for key, count in count_summary.items():
                    output += f"{key:<15}:\t{count}\n"

            case _:  # table format
                output = Table(
                    Column(header='⚔️', overflow='fold', justify='center'),
                    Column(header='Endpoints Count', overflow='fold'),
                    title=table_title,
                )

                for key, count in count_summary.items():
                    output.add_row(*[key, str(count)])

        return output
