import json, os, subprocess, sys, base64, unittest
HERE = os.path.dirname(os.path.abspath(__file__)); sys.path.insert(0, os.path.join(HERE, '..', 'tools'))
import encfmt
NODE = os.path.join(HERE, '..', '.venv', 'bin', 'node')
class Parity(unittest.TestCase):
    @classmethod
    def setUpClass(cls): subprocess.check_call([sys.executable, os.path.join(HERE, 'gen_vectors.py')], stdout=subprocess.DEVNULL)
    def test_roundtrip(self):
        r = subprocess.run([NODE, os.path.join(HERE, 'parity.test.js')], capture_output=True, text=True)
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        out = json.load(open(os.path.join(HERE, 'js_out.json')))
        k = encfmt.Keys(bytes(range(32)))
        for c in out['cases']:
            f, body, e = encfmt.open_tiddler(k, c['title'], base64.b64decode(c['blob']), c['rev'])
            self.assertEqual(encfmt.join_tiddler(f, body, e)['text'], c['text'])
        self.assertEqual(encfmt.open_manifest(k, base64.b64decode(out['manifest']))['counter'], 43)
    def test_python_rejects_malformed_authentic_payloads(self):
        v = json.load(open(os.path.join(HERE, 'vectors.json'))); k = encfmt.Keys(bytes(range(32))); d = base64.b64decode
        self.assertEqual(len(encfmt.open_tiddler(k, 't', d(v['ok_file']), 1)[1]), 1)
        self.assertEqual(encfmt.open_manifest(k, d(v['ok_manifest']))['counter'], 42)
        msgs = set()
        for b in v['bad_files']:
            with self.assertRaises(ValueError) as cm: encfmt.open_tiddler(k, 't', d(b), 1)
            msgs.add(str(cm.exception)); self.assertNotIn('MAC', str(cm.exception))   # rejected by validation, not by the tag
        for b in v['bad_manifests']:
            with self.assertRaises(ValueError) as cm: encfmt.open_manifest(k, d(b))
            msgs.add(str(cm.exception)); self.assertNotIn('MAC', str(cm.exception))
        self.assertGreaterEqual(len(msgs), 8)
if __name__ == '__main__': unittest.main()
