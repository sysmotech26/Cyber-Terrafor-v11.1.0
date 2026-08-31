import json, tempfile, unittest, sys
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]; sys.path.insert(0,str(ROOT/'src'))
import platform_engine as pe
class PlatformTests(unittest.TestCase):
    def test_vulnerability_import_lookup(self):
        with tempfile.TemporaryDirectory() as d:
            p=Path(d)/'v.json'; p.write_text(json.dumps([{'id':'CVE-TEST-1','cvss_v4':9.1,'epss':.7,'cwe':'CWE-79'}]))
            self.assertEqual(pe.import_vulnerabilities(p)['imported'],1); self.assertEqual(pe.vulnerability_lookup('CVE-TEST-1')['cvss4'],9.1)
    def test_remediation_lifecycle(self):
        r=pe.create_remediation('finding-test','alice','critical',1); self.assertEqual(r['status'],'open'); pe.update_remediation(r['id'],'in_progress'); v=pe.verify_finding('finding-test'); self.assertEqual(v['status'],'verified')
    def test_asm(self):
        r=pe.attack_surface_snapshot('localhost',prefixes=['www']); self.assertIn('assets',r); self.assertIn('changes',r)
    def test_cloud_export(self):
        with tempfile.TemporaryDirectory() as d:
            p=Path(d)/'cloud.json'; p.write_text(json.dumps({'provider':'aws','public':True,'logging':False,'encrypted':False}))
            self.assertGreaterEqual(len(pe.cloud_config_audit(p)['findings']),2)
    def test_threat_intel(self):
        with tempfile.TemporaryDirectory() as d:
            p=Path(d)/'ti.json'; p.write_text(json.dumps([{'ioc':'203.0.113.10','type':'ip','verdict':'malicious','confidence':.9}]))
            pe.threat_intel_import(p); self.assertEqual(pe.threat_intel_lookup('203.0.113.10')['verdict'],'malicious')
if __name__=='__main__': unittest.main()
