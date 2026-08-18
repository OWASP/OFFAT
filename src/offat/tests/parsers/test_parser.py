import tempfile

import unittest
from unittest.mock import patch, MagicMock
from ...parsers import BaseParser, create_parser
from ...parsers.openapi import OpenAPIv3Parser


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


class TestCreateParserFromUrl(unittest.TestCase):
    _YAML_SPEC = """
openapi: 3.0.0
info:
  title: Test
  version: "1.0"
paths:
  /api/render:
    post:
      operationId: operationId
      responses:
        "201":
          description: Rendered result
servers:
  - url: https://someserver.com
"""

    _JSON_SPEC = (
        '{"openapi": "3.0.0", "info": {"title": "Test", "version": "1.0"},'
        ' "paths": {"/api/render": {"post": {"operationId": "operationId",'
        ' "responses": {"201": {"description": "ok"}}}}},'
        ' "servers": [{"url": "https://someserver.com"}]}'
    )

    def _create_from_url(self, body):
        fake_res = MagicMock()
        fake_res.status_code = 200
        fake_res.text = body
        with patch("offat.parsers.http_get", return_value=fake_res):
            return create_parser("https://example.com/openapi.yaml")

    def test_yaml_spec_from_url(self):
        parser = self._create_from_url(self._YAML_SPEC)
        self.assertIsInstance(parser, OpenAPIv3Parser)
        self.assertEqual(parser.specification.get("openapi"), "3.0.0")

    def test_json_spec_from_url(self):
        parser = self._create_from_url(self._JSON_SPEC)
        self.assertIsInstance(parser, OpenAPIv3Parser)
        self.assertEqual(parser.specification.get("openapi"), "3.0.0")
