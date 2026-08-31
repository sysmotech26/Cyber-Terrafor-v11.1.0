import os, sys, tempfile, unittest, time
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))
import admin_panel

class AuthEnterpriseTests(unittest.TestCase):
    def test_totp_roundtrip_and_window(self):
        secret=admin_panel.new_totp_secret()
        code=admin_panel.totp(secret)
        self.assertTrue(admin_panel.verify_totp(secret, code))
        self.assertFalse(admin_panel.verify_totp(secret, '123'))

    def test_roles_are_separated(self):
        self.assertIn('assessments', admin_panel.ROLES['analyst'])
        self.assertNotIn('vault', admin_panel.ROLES['analyst'])
        self.assertNotIn('users', admin_panel.ROLES['security_admin'])
        self.assertEqual(admin_panel.ROLES['viewer'], {'dashboard','reports'})

    def test_api_scope_set(self):
        self.assertEqual(admin_panel.API_SCOPES, {'status','heartbeat','event'})

if __name__=='__main__': unittest.main()
