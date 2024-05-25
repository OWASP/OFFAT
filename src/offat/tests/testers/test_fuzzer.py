
import unittest
from ...tester.fuzzer import fill_params

class TestFuzzer(unittest.TestCase):
    def test_fill_params(self):
        params_in = [
            {
                "in": "body", 
                "name": "text/plain", 
                "description": "Write your text here", 
                "required": True, 
                "schema": {"type": "string"}
            }
        ]

        params_out = fill_params(params = params_in[:], is_v3 = True)

        self.assertTrue(
            'value' in params_out[0].keys(),
            "'value' should exist"
        )

        self.assertTrue(
            'type' in params_out[0].keys(),
            "'type' should exist"
        )

        self.assertTrue(
            'schema' not in params_out[0].keys(),
            "'schema' should be gone"
        )
