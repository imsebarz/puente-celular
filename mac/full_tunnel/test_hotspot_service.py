import unittest
from types import SimpleNamespace
from unittest.mock import patch

import hotspot_service as service


class HotspotActivationTests(unittest.TestCase):
    def test_trigger_requires_console_user_wifi_gateway_and_physical_route(self):
        profile = {'uid': 502, 'phone': '172.20.10.1', 'wifi': 'en0'}
        with (patch.object(service.os, 'stat', return_value=SimpleNamespace(st_uid=502)) as stat,
              patch.object(service, 'run', return_value='172.20.10.1\n') as gateway,
              patch.object(service, 'route', return_value={'interface': 'en0'}) as route):
            self.assertTrue(service.on_hotspot(profile))
            route.return_value = {'interface': 'en10'}
            self.assertFalse(service.on_hotspot(profile))
            route.return_value = {'interface': 'en0'}
            gateway.return_value = '10.0.0.1'
            self.assertFalse(service.on_hotspot(profile))
            gateway.return_value = profile['phone']
            stat.return_value = SimpleNamespace(st_uid=503)
            self.assertFalse(service.on_hotspot(profile))

    def test_yields_to_active_or_connecting_vpn(self):
        for value, expected in [('(Disconnected)', True), ('(Connected)', False),
                                ('(Connecting)', False), ('', False)]:
            with self.subTest(value=value), patch.object(service, 'run', return_value=value):
                self.assertEqual(service.vpn_clear(), expected)
