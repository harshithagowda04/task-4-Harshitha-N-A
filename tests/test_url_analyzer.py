import unittest
from detection.url_analyzer import analyze_url, extract_urls

class URLAnalyzerTests(unittest.TestCase):
    def test_ip_based_url(self): self.assertTrue(any('IP address' in x for x in analyze_url('http://192.0.2.4/login')['indicators']))
    def test_shortener(self): self.assertTrue(any('shortener' in x for x in analyze_url('https://bit.ly/a')['indicators']))
    def test_invalid_empty(self): self.assertFalse(analyze_url('')['valid'])
    def test_extract(self): self.assertEqual(extract_urls('See https://example.com/x. and www.test.example'),['https://example.com/x','www.test.example'])

if __name__=='__main__': unittest.main()
