from unittest import TestCase
from unittest.mock import Mock, patch

import temporary_test as session
from prepare import wired_endpoint


class SessionTests(TestCase):
    def test_deadline_exits_without_signal(self):
        engine = Mock()
        engine.poll.return_value = None
        with (patch.object(session.time, 'monotonic', side_effect=[0, 3, 3, 4]),
              patch.object(session.time, 'sleep') as sleep,
              patch.object(session, 'route', return_value={'interface': 'utun7'}),
              patch.object(session, 'has_address', return_value=True) as dns):
            session.monitor(engine, None, 'fd00::1', 'utun7', 4)
        self.assertEqual([call.args for call in sleep.call_args_list], [(3,), (1,)])
        dns.assert_called_once()

    def test_native_dns_ignores_scoped_wifi(self):
        output = ('resolver #1\n nameserver[0] : 172.30.255.2\nresolver #2\n'
                  ' nameserver[0] : 10.0.0.1\nDNS configuration (for scoped queries)\n')
        with patch.object(session, 'run', return_value=output):
            self.assertEqual(session.native_dns(), ['172.30.255.2'])

    def test_route_reads_interface_and_gateway(self):
        with patch.object(session, 'run', return_value=' destination: default\n gateway: 10.0.0.1\n interface: en0\n'):
            self.assertEqual(session.route('1.1.1.1')['interface'], 'en0')

    def test_missing_dns_answer_is_failure(self):
        with patch.object(session, 'run', return_value=';; connection timed out\n'):
            self.assertFalse(session.has_address(session.DNS))

    def test_wired_mode_rejects_wireless_device(self):
        with patch('prepare.subprocess.run') as command:
            command.return_value.stdout = b'{"result":{"connectionProperties":{"transportType":"wireless","tunnelState":"connected","tunnelIPAddress":"fd00::1"}}}'
            with self.assertRaises(ValueError):
                wired_endpoint('phone')
