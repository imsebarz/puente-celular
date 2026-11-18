import base64
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import shutil
import stat
import subprocess
import tempfile
import unittest

spec = importlib.util.spec_from_file_location('pairing', Path(__file__).parents[1] / 'tools/create_pairing.py')
pairing = importlib.util.module_from_spec(spec)
spec.loader.exec_module(pairing)

@unittest.skipUnless(shutil.which('openssl'), 'OpenSSL unavailable')
class PairingTests(unittest.TestCase):
    def test_valid_bundle_and_pin(self):
        with tempfile.TemporaryDirectory() as root:
            output = pairing.generate(Path(root) / 'secrets', '172.20.10.1')
            self.assertEqual(stat.S_IMODE(output.stat().st_mode), 0o700)
            server = json.loads((output/'iphone-pairing.json').read_text())
            client = json.loads((output/'mac-config.json').read_text())
            for path in output.iterdir():
                self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)
            self.assertEqual(server['token'], client['token'])
            self.assertEqual(len(bytes.fromhex(client['token'])), 32)
            self.assertEqual(server['certificate_sha256'], client['certificate_sha256'])
            p12 = Path(root)/'identity.p12'; p12.write_bytes(base64.b64decode(server['pkcs12_base64']))
            password = Path(root)/'password'; password.write_text(server['pkcs12_password'])
            pem = subprocess.run(['openssl', 'pkcs12', '-in', str(p12), '-passin', f'file:{password}', '-clcerts', '-nokeys'], check=True, capture_output=True).stdout
            der = subprocess.run(['openssl', 'x509', '-outform', 'DER'], input=pem, check=True, capture_output=True).stdout
            self.assertEqual(hashlib.sha256(der).hexdigest(), client['certificate_sha256'])
            with self.assertRaises(FileExistsError): pairing.generate(output, '172.20.10.1')
    def test_rejects_nonlocal_endpoint(self):
        with tempfile.TemporaryDirectory() as root:
            for host in ('8.8.8.8', '127.0.0.1', '0.0.0.0', '::', '::1', '224.0.0.1'):
                with self.assertRaises(ValueError): pairing.generate(Path(root)/'bad', host)
            self.assertFalse((Path(root)/'bad').exists())

if __name__ == '__main__': unittest.main()
