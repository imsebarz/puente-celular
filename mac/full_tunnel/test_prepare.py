import json
import os
from pathlib import Path
import tempfile
import unittest
from prepare import Config, configuration, endpoint, write_private

class PreparationTests(unittest.TestCase):
    def config(self, host):
        return Config(host, 49443, 'a'*64, 'b'*64, 'local', 'x'*32)
    def test_usb(self):
        config = configuration(self.config('fdd8:eab6:9eed::1'))
        self.assertEqual(config['inbounds'][0]['route_exclude_address'], ['fdd8:eab6:9eed::1/128'])
    def test_hotspot(self):
        config = configuration(self.config('172.20.10.1'))
        self.assertEqual(config['inbounds'][0]['route_exclude_address'], ['172.20.10.1/32'])
    def test_no_direct_fallback(self):
        config = configuration(self.config('172.20.10.1'))
        self.assertEqual([o['type'] for o in config['outbounds']], ['socks'])
        self.assertEqual(config['route']['final'], 'phone')
        self.assertEqual(config['dns']['servers'][0]['detour'], 'phone')
        self.assertTrue(config['dns']['servers'][0]['tls']['enabled'])
    def test_no_relay_secret_in_engine(self):
        text = json.dumps(configuration(self.config('172.20.10.1')))
        self.assertNotIn('b'*64, text)
        self.assertNotIn('a'*64, text)
    def test_endpoints(self):
        for value in ['1.1.1.1','127.0.0.1','::','fe80::1','224.0.0.1','example.com']:
            with self.assertRaises(ValueError): endpoint(value)
    def test_private_no_overwrite(self):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d)/'config.json'
            write_private(p, {'test': True})
            self.assertEqual(p.stat().st_mode & 0o777, 0o600)
            with self.assertRaises(FileExistsError): write_private(p, {})
            link = Path(d)/'link'; link.symlink_to(p)
            with self.assertRaises(FileExistsError): write_private(link, {})
    def test_port(self):
        for port in [0,65536,True]:
            with self.assertRaises(ValueError): configuration(self.config('172.20.10.1'), port)

if __name__ == '__main__': unittest.main()
