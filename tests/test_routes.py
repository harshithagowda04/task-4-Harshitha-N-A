import os
import tempfile
import unittest
import re
import app as app_module

class RouteTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory(); app_module.app.config.update(TESTING=True,DATABASE=os.path.join(self.temp.name,'test.sqlite3'))
        with app_module.app.app_context(): app_module.init_db()
        self.client=app_module.app.test_client()
        page=self.client.get('/analyzer').get_data(as_text=True)
        self.token=re.search(r'name="csrf_token" value="([^"]+)"',page).group(1)
    def tearDown(self): self.temp.cleanup()
    def test_pages(self):
        for path in ('/','/dashboard','/analyzer','/url-scanner','/awareness','/samples','/history','/settings','/about'): self.assertEqual(self.client.get(path).status_code,200,path)
    def test_empty_validation(self): self.assertEqual(self.client.post('/analyzer',data={'csrf_token':self.token,'sender':'','subject':'','body':''}).status_code,400)
    def test_persistence_and_report_download(self):
        response=self.client.post('/analyzer',data={'csrf_token':self.token,'sender':'a@example.com','subject':'Hello','body':'Your regular update is available. No action needed.'},follow_redirects=True)
        self.assertEqual(response.status_code,200); self.assertIn(b'Analysis report',response.data)
        download=self.client.get('/report/1.txt'); self.assertEqual(download.status_code,200); self.assertIn(b'PHISHGUARD',download.data)
        self.assertEqual(self.client.get('/history').status_code,200)

if __name__=='__main__': unittest.main()
