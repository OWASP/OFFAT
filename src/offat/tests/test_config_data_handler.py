from pathlib import Path
import unittest

import yaml

from ..config_data_handler import populate_user_data, validate_config_file_data


class TestReadmeConfig(unittest.TestCase):
    def setUp(self):
        readme = Path(__file__).resolve().parents[2] / 'README.md'
        example = readme.read_text(encoding='utf-8').split('```yaml', 1)[1].split('```', 1)[0]
        self.config = yaml.safe_load(example)

    def test_readme_config_validates(self):
        self.assertEqual(validate_config_file_data(self.config), self.config)

    def test_readme_actor_settings_populate_requests(self):
        for index, name, user_id, city in (
            (0, 'actor1', 145, 'london'),
            (1, 'actor2', 199, 'leeds'),
        ):
            with self.subTest(actor=name):
                actor = self.config['actors'][index][name]
                tests = [{
                    'body_params': [{'name': 'email', 'value': ''}],
                    'query_params': [{'name': 'id', 'value': 0}, {'name': 'city', 'value': ''}],
                    'path_params': [],
                    'kwargs': {'headers': {'Accept': 'application/json'}},
                }]
                populated = populate_user_data(actor, name, tests)[0]
                self.assertEqual(populated['query_params'], [
                    {'name': 'id', 'value': user_id}, {'name': 'city', 'value': city},
                ])
                self.assertEqual(populated['body_params'][0]['value'],
                                 'actorone@example.com' if index == 0 else 'actortwo@example.com')
                self.assertEqual(populated['kwargs']['headers'], {
                    'Accept': 'application/json',
                    'Authorization': f'Bearer [Token{index + 1}]',
                    'User-Agent': f'offat-{name}',
                })
                self.assertEqual(populated['test_actor_name'], name)
                self.assertEqual(tests[0]['query_params'][0]['value'], 0)
