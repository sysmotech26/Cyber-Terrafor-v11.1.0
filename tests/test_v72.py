import tempfile, unittest, sys
from pathlib import Path
PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT / 'src'))
from infrastructure_vault import Vault, VaultError
class VaultTests(unittest.TestCase):
    def test_roundtrip_and_wrong_password(self):
        with tempfile.TemporaryDirectory() as d:
            v=Vault(d,password='correct horse battery staple')
            v.put('site1',{'ssh_user':'alice','ssh_key':'SECRET'})
            self.assertEqual(v.get('site1')['ssh_user'],'alice')
            with self.assertRaises(VaultError): Vault(d,password='wrong password')
    def test_delete(self):
        with tempfile.TemporaryDirectory() as d:
            v=Vault(d,password='a'*16); v.put('x',{'a':'b'}); v.delete('x'); self.assertFalse(v.has('x'))
if __name__=='__main__': unittest.main()

class AdapterTests(unittest.TestCase):
    def test_local_backup_snapshot(self):
        from infrastructure_adapters import LocalBackupAdapter
        with tempfile.TemporaryDirectory() as d:
            Path(d,'admin.json').write_text('{"version":"7.2.0"}')
            result=LocalBackupAdapter(d).create_snapshot()
            self.assertTrue(result['backup'].endswith('.tar.gz'))
            self.assertTrue((Path(d)/'backups'/result['backup']).exists())

if __name__=='__main__':
    unittest.main()

class EnterpriseEngineTests(unittest.TestCase):
    def test_compliance_mapping(self):
        from enterprise_engine import compliance_map
        rows = compliance_map([{"title":"HSTS not advertised","module":"Web Security Posture","severity":"medium"}])
        self.assertEqual(rows[0]["finding"], "HSTS not advertised")
        self.assertTrue(rows[0]["controls"])

    def test_evidence_manifest(self):
        from enterprise_engine import evidence_manifest
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / 'report.json'; p.write_text('{"ok":true}')
            out = Path(d) / 'manifest.json'
            m = evidence_manifest([p], out)
            self.assertEqual(len(m['artifacts']), 1)
            self.assertTrue(out.exists())
            self.assertEqual(len(m['artifacts'][0]['sha256']), 64)
