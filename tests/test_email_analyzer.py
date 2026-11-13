import unittest
from detection.email_analyzer import analyze_email

class EmailAnalyzerTests(unittest.TestCase):
    def test_safe_message(self):
        self.assertEqual(analyze_email('alerts@library.example','Monthly reading summary','Hello Alex, your monthly summary is ready. No action is required.')['verdict'],'SAFE')
    def test_phishing_message(self):
        result=analyze_email('security@bank-alert.example','Your account is suspended','Urgent action required. Verify your account immediately at http://192.0.2.12/login. Reply with your password and payment details.')
        self.assertEqual(result['verdict'],'PHISHING')
    def test_keyword_and_url_extraction(self):
        result=analyze_email('x@example.com','Verify your account','Click immediately https://bit.ly/example')
        self.assertIn('verify your account',result['keywords']); self.assertEqual(result['urls'],['https://bit.ly/example'])

if __name__=='__main__': unittest.main()
