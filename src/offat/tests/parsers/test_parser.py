import tempfile

import unittest
from ...parsers import BaseParser


class TestBaseParser(unittest.TestCase):
    def test_BaseParser(self):
        tmp_spec = tempfile.NamedTemporaryFile(mode="+a", encoding="utf-8")
        tmp_spec.write("""
{
  "openapi": "3.0.0",
  "paths": {
    "/api/render": {
      "post": {
        "operationId": "operationId",
        "summary": "",
        "description": "description",
        "parameters": [],
        "requestBody": {
          "required": true,
          "description": "Write your text here",
          "content": { "text/plain": { "schema": { "type": "string" } } }
        },
        "responses": { "201": { "description": "Rendered result" } },
        "tags": ["App controller"]
      }
    },
  },
  "info": {
    "title": "Test",
    "description": "info -> description",
    "version": "1.0",
    "contact": {}
  },
  "tags": [],
  "servers": [{ "url": "https://someserver.com" }],
  "components": {
    "schemas": {
    }
  }
}
"""
    )
        tmp_spec.flush()
        obj = BaseParser(tmp_spec.name)

        self.assertTrue(
            obj.is_v3,
            "Provided JSON is v3"
        )

        end_points = list(obj.specification.get('paths').keys())
        self.assertTrue(
            '/api/render' in end_points,
            "Spec has '/api/render'"
        )
