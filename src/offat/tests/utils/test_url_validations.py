import unittest
from ...utils import is_valid_url


class TestUrls(unittest.TestCase):
    def test_valid_urls(self):
        urls = [
            'https://example.com',
            'https://owasp.org/OFFAT/',
            # 'http://localhost:8000/test',
            'http://127.0.0.1:8001/url',
        ]
        for url in urls:
            self.assertTrue(is_valid_url(url=url), f'Failed to validate url: {url}')

    def test_invalid_urls(self):
        urls = [
            'owasp',
            'ftp://example/',
            '\0\0alkdsjlatest',
            '" OR 1==1 -- -'
        ]
        for url in urls:
            assert is_valid_url(url=url) == False
