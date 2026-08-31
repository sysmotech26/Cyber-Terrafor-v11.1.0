import json, tempfile, unittest, sys
from pathlib import Path
PROJECT_ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(PROJECT_ROOT/'src'))
import enterprise_upgrade as eu

class EnterpriseUpgradeTests(unittest.TestCase):
    def test_risk_engine(self):
        r=eu.enterprise_risk([{"title":"HSTS not advertised","severity":"medium","confidence":"high","references":["CWE-319"],"remediation":"Enable HSTS"}],80,True,80)
        self.assertGreater(r['score'],0); self.assertIn(r['level'],{'LOW','MEDIUM','HIGH','CRITICAL'})
    def test_secret_scan(self):
        with tempfile.TemporaryDirectory() as d:
            p=Path(d)/'x.env'; p.write_text('AWS=AKIA1234567890ABCDEF\n')
            r=eu.scan_secrets(d); self.assertGreaterEqual(r['count'],1)
    def test_container_audit(self):
        with tempfile.TemporaryDirectory() as d:
            Path(d,'Dockerfile').write_text('FROM ubuntu\nUSER root\nENV PASSWORD=supersecret\n')
            r=eu.container_audit(d); self.assertGreaterEqual(len(r['findings']),2)
    def test_evidence_seal(self):
        with tempfile.TemporaryDirectory() as d:
            p=Path(d)/'a.json'; p.write_text('{"ok":true}')
            out=Path(d)/'seal.json'; r=eu.evidence_seal([p],out); self.assertEqual(len(r['artifacts'][0]['sha256']),64); self.assertTrue(out.exists())

if __name__=='__main__': unittest.main()
