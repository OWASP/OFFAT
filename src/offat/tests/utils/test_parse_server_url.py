import unittest
from pytest import raises
from ...utils import parse_server_url


class TestParseUrls(unittest.TestCase):
    def test_valid_urls(self):
        urls = [
            "https://example.com",
            "https://owasp.org/OFFAT/",
            "http://localhost:8000/test",
            "http://127.0.0.1:8001/url/1",
        ]
        for url in urls:
            scheme, host, port, basepath = parse_server_url(url=url)
            self.assertIn(
                scheme, ["http", "https"], f"Failed to validate url scheme: {url}"
            )
            self.assertIn(
                host,
                ["example.com", "owasp.org", "localhost", "127.0.0.1"],
                "Host does not match expected test cases",
            )
            self.assertIn(
                port,
                [80, 443, 8000, 8001],
                "Port does not match according to test case",
            )
            self.assertIn(basepath, ["", "/OFFAT/", "/test", "/url/1"])

    def test_invalid_urls(self):
        urls = ["owasp", "ftp://example/", "\0\0alkdsjlatest", '" OR 1==1 -- -']
        for url in urls:
            with raises(ValueError):
                parse_server_url(url=url)
