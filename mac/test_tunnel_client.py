import asyncio
from dataclasses import replace
import hashlib
import json
import os
from pathlib import Path
import socket
import ssl
import struct
import subprocess
import tempfile
import unittest
from unittest.mock import patch

import tunnel_client as tc


class AddressTests(unittest.TestCase):
    def test_ipv4_ipv6_domain_roundtrip(self):
        for host in ('203.0.113.4', '2001:db8::9', 'example.com'):
            raw = tc.encode_address(host, 443)
            decoded = tc.decode_address(raw)
            self.assertEqual(decoded, (host, 443, len(raw)))
    def test_rejects_truncation(self):
        for data in (b'', b'\1\0', b'\4\0', b'\3\0\0\0', b'\3\3a', b'\3\1\xff\0\1', b'\7'):
            with self.subTest(data=data), self.assertRaises(tc.ProtocolError): tc.decode_address(data)
    def test_domain_is_not_resolved(self):
        with patch('socket.getaddrinfo', side_effect=AssertionError('DNS leaked')):
            self.assertEqual(tc.decode_address(tc.encode_address('never-resolve.example', 53))[0], 'never-resolve.example')
    def test_config_permissions_and_fields(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'config.json'
            data = dict(server_host='172.20.10.1', server_port=49443, certificate_sha256='a'*64,
                        token='b'*64, socks_username='local', socks_password='c'*32)
            path.write_text(json.dumps(data)); path.chmod(0o600)
            self.assertEqual(tc.Config.load(path).server_port, 49443)
            if os.name == 'posix':
                path.chmod(0o644)
                with self.assertRaises(ValueError): tc.Config.load(path)
                path.chmod(0o600)
            for key, value in [('server_host','8.8.8.8'), ('server_host','127.0.0.1'), ('server_port', True),
                               ('certificate_sha256','not-a-pin'), ('socks_password','short')]:
                changed = dict(data); changed[key] = value; path.write_text(json.dumps(changed))
                with self.subTest(key=key, value=value), self.assertRaises(ValueError): tc.Config.load(path)


class FrameTests(unittest.IsolatedAsyncioTestCase):
    async def test_fragmented_data_frame(self):
        reader = asyncio.StreamReader()
        task = asyncio.create_task(tc.read_frame(reader))
        for part in (b'D\0', b'\0\0\3', b'a', b'bc'):
            reader.feed_data(part); await asyncio.sleep(0)
        self.assertEqual(await task, (b'D', b'abc'))
    async def test_rejects_frame_before_payload_allocation(self):
        for header in (b'X'+struct.pack('!I',0), b'F'+struct.pack('!I',1),
                       b'E'+struct.pack('!I',4097), b'D'+struct.pack('!I',65508)):
            reader = asyncio.StreamReader(); reader.feed_data(header)
            with self.assertRaises(tc.ProtocolError): await tc.read_frame(reader)
    async def test_empty_datagram_allowed(self):
        reader = asyncio.StreamReader(); reader.feed_data(b'D\0\0\0\0')
        self.assertEqual(await tc.read_frame(reader), (b'D', b''))
    async def test_python310_timeout_context(self):
        with self.assertRaises(asyncio.TimeoutError):
            async with tc._timeout(.01): await asyncio.sleep(1)

    async def test_relay_failure_cancels_sibling_task(self):
        cancelled = asyncio.Event()
        class BrokenReader:
            async def read(self, size):
                await asyncio.sleep(0)
                raise tc.ProtocolError('test source failure')
        class WaitingReader:
            async def readexactly(self, size):
                try:
                    await asyncio.Event().wait()
                finally:
                    cancelled.set()
        with self.assertRaises(tc.ProtocolError):
            await tc.relay_tcp(BrokenReader(), None, WaitingReader(), None)
        self.assertTrue(cancelled.is_set())


class DatagramCollector(asyncio.DatagramProtocol):
    def __init__(self): self.queue = asyncio.Queue()
    def datagram_received(self, data, addr): self.queue.put_nowait(data)


class TLSIntegrationTests(unittest.IsolatedAsyncioTestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp = tempfile.TemporaryDirectory()
        root = Path(cls.temp.name)
        cls.cert = root / 'cert.pem'; cls.key = root / 'key.pem'
        subprocess.run(['openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes',
                        '-keyout', str(cls.key), '-out', str(cls.cert), '-days','1',
                        '-subj','/CN=local-fixture'], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        der = ssl.PEM_cert_to_DER_cert(cls.cert.read_text())
        cls.pin = hashlib.sha256(der).hexdigest()
    @classmethod
    def tearDownClass(cls): cls.temp.cleanup()
    async def asyncSetUp(self):
        self.remote_tasks = set(); self.remote_writers = set(); self.headers = []
        self.received_before_auth = []; self.tcp_result = b''
        self.phone_reply = {'ok': True}
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        context.load_cert_chain(self.cert, self.key)
        self.remote = await asyncio.start_server(self.fake_phone, '127.0.0.1', 0, ssl=context)
        self.config = tc.Config('127.0.0.1', self.remote.sockets[0].getsockname()[1], self.pin,
                                'b'*64, 'local', 'c'*32)
        self.handler = tc.SocksServer(self.config)
        self.socks = await asyncio.start_server(self.handler.handle, '127.0.0.1', 0)
        self.socks_port = self.socks.sockets[0].getsockname()[1]
    async def asyncTearDown(self):
        self.socks.close(); await self.socks.wait_closed(); await self.handler.close()
        self.remote.close(); await self.remote.wait_closed()
        for writer in list(self.remote_writers): await tc.close_writer(writer)
        for task in list(self.remote_tasks): task.cancel()
        await asyncio.gather(*list(self.remote_tasks), return_exceptions=True)
    async def fake_phone(self, reader, writer):
        task = asyncio.current_task(); self.remote_tasks.add(task); self.remote_writers.add(writer)
        try:
            line = await reader.readline()
            if not line: return
            self.received_before_auth.append(line)
            header = json.loads(line); self.headers.append(header)
            if header.get('token') != 'b'*64:
                writer.write(b'{"ok":false}\n'); await writer.drain(); return
            writer.write(json.dumps(self.phone_reply).encode() + b'\n'); await writer.drain()
            while True:
                kind, data = await tc.read_frame(reader)
                if kind == b'F':
                    if header['transport'] == 'tcp':
                        await tc.send_frame(writer,b'D',b'after-client-fin')
                    await tc.send_frame(writer,b'F'); return
                if kind != b'D': return
                if header['transport'] == 'tcp': self.tcp_result += data
                await tc.send_frame(writer,b'D',data)
        except (asyncio.IncompleteReadError, ConnectionError, tc.ProtocolError, asyncio.CancelledError): pass
        finally:
            await tc.close_writer(writer)
            self.remote_tasks.discard(task); self.remote_writers.discard(writer)
    async def connect_socks(self, password=None):
        reader, writer = await asyncio.open_connection('127.0.0.1', self.socks_port)
        writer.write(b'\5\1\2'); await writer.drain()
        self.assertEqual(await reader.readexactly(2), b'\5\2')
        username = b'local'; password = (password or 'c'*32).encode()
        writer.write(b'\1'+bytes([len(username)])+username+bytes([len(password)])+password)
        await writer.drain()
        return reader, writer
    async def request(self, reader, writer, command, host, port):
        writer.write(bytes([5, command, 0])+tc.encode_address(host,port)); await writer.drain()
        version, result, reserved, kind = await reader.readexactly(4)
        address, port = await tc.read_address(reader, kind)
        self.assertEqual(version, 5); self.assertEqual(reserved, 0)
        return result, address, port
    async def test_tcp_domain_and_halfclose(self):
        reader, writer = await self.connect_socks()
        self.assertEqual(await reader.readexactly(2), b'\1\0')
        self.assertEqual((await self.request(reader,writer,1,'example.com',443))[0],0)
        writer.write(b'hello'); await writer.drain()
        self.assertEqual(await reader.readexactly(5), b'hello')
        writer.write_eof()
        self.assertEqual(await asyncio.wait_for(reader.read(),3),b'after-client-fin')
        self.assertEqual(self.headers[0]['host'],'example.com')
        self.assertEqual(self.headers[0]['transport'],'tcp')
        await tc.close_writer(writer)
    async def test_ipv6_destination(self):
        reader, writer = await self.connect_socks(); await reader.readexactly(2)
        self.assertEqual((await self.request(reader,writer,1,'2001:db8::4',443))[0],0)
        self.assertEqual(self.headers[0]['host'],'2001:db8::4')
        await tc.close_writer(writer)
    async def test_wrong_password_no_tunnel(self):
        reader, writer = await self.connect_socks(password='wrong')
        self.assertEqual(await reader.readexactly(2),b'\1\1')
        self.assertEqual(await reader.read(),b'')
        self.assertEqual(self.headers,[])
        await tc.close_writer(writer)
    async def test_no_anonymous_auth(self):
        reader, writer = await asyncio.open_connection('127.0.0.1', self.socks_port)
        writer.write(b'\5\1\0'); await writer.drain()
        self.assertEqual(await reader.readexactly(2), b'\5\xff')
        await tc.close_writer(writer)
    async def test_pin_rejection_sends_no_application_data(self):
        with self.assertRaisesRegex(tc.ProtocolError, 'pin mismatch'):
            await tc.open_tunnel(replace(self.config,certificate_sha256='0'*64),'tcp','example.com',443)
        await asyncio.sleep(.05)
        self.assertEqual(self.received_before_auth,[])
    async def test_bad_server_token(self):
        with self.assertRaisesRegex(tc.ProtocolError,'refused'):
            await tc.open_tunnel(replace(self.config,token='0'*64),'tcp','example.com',443)
    async def test_bind_rejected(self):
        reader, writer = await self.connect_socks(); await reader.readexactly(2)
        self.assertEqual((await self.request(reader,writer,2,'0.0.0.0',0))[0],7)
        self.assertEqual(self.headers,[])
        await tc.close_writer(writer)

    async def test_updated_phone_allows_40_live_connections_and_legacy_keeps_30(self):
        self.phone_reply['max_sessions'] = 96
        writers = []
        try:
            for _ in range(40):
                reader, writer = await self.connect_socks()
                writers.append(writer)
                await reader.readexactly(2)
                reply, _, _ = await asyncio.wait_for(self.request(reader, writer, 1, 'site.example', 443), 2)
                self.assertEqual(reply, 0)
            self.assertEqual(self.handler.phone_slots.used, 40)
            self.assertEqual(self.handler.phone_slots.limit, 88)
            await self.handler.phone_slots.configure(None)
            self.assertEqual(self.handler.phone_slots.limit, 30)
            with self.assertRaises(asyncio.TimeoutError):
                await asyncio.wait_for(self.handler.phone_slots.acquire(), 0.02)
            self.assertEqual(self.handler.phone_slots.used, 40)
        finally:
            await asyncio.gather(*(tc.close_writer(writer) for writer in writers))

    async def test_desktop_burst_and_phone_backpressure(self):
        self.handler.phone_slots = tc.PhoneSlots(ceiling=17)
        clients = []
        try:
            for _ in range(18):
                reader, writer = await self.connect_socks()
                self.assertEqual(await reader.readexactly(2), b'\x01\x00')
                clients.append((reader, writer))
            for reader, writer in clients[:17]:
                reply, _, _ = await self.request(reader, writer, 1, 'example.com', 443)
                self.assertEqual(reply, 0)
            pending = asyncio.create_task(self.request(*clients[17], 1, 'example.com', 443))
            await asyncio.sleep(0.03)
            self.assertFalse(pending.done())
            self.assertEqual(len(self.headers), 17)
            await tc.close_writer(clients[0][1])
            reply, _, _ = await asyncio.wait_for(pending, 3)
            self.assertEqual(reply, 0)
        finally:
            await asyncio.gather(*(tc.close_writer(writer) for _, writer in clients))
    async def test_udp_443_pressure_across_associations_preserves_tcp_and_reclaims_idle(self):
        with patch.object(tc, 'MAX_UDP_443_SESSIONS', 1):
            self.handler.udp443 = tc.UDP443Budget()
        self.handler.phone_slots = tc.PhoneSlots(ceiling=2)
        controls = []
        endpoints = []
        collector = DatagramCollector()
        transport, _ = await asyncio.get_running_loop().create_datagram_endpoint(
            lambda: collector, local_addr=('127.0.0.1', 0))
        try:
            for _ in range(2):
                reader, writer = await self.connect_socks()
                controls.append(writer)
                await reader.readexactly(2)
                result, host, port = await self.request(reader, writer, 3, '0.0.0.0', 0)
                self.assertEqual(result, 0)
                endpoints.append((host, port))
            with patch.object(tc, 'UDP_443_PRESSURE_IDLE', 0.2):
                first = bytes(3) + tc.encode_address('first.example', 443) + b'one'
                second = bytes(3) + tc.encode_address('second.example', 443) + b'two'
                transport.sendto(first, endpoints[0])
                self.assertEqual(await asyncio.wait_for(collector.queue.get(), 1), first)
                transport.sendto(second, endpoints[1])
                with self.assertRaises(asyncio.TimeoutError):
                    await asyncio.wait_for(collector.queue.get(), 0.05)
                reader, writer = await self.connect_socks()
                controls.append(writer)
                await reader.readexactly(2)
                self.assertEqual((await self.request(reader, writer, 1, 'web.example', 443))[0], 0)
                self.assertEqual(await asyncio.wait_for(collector.queue.get(), 3), second)
                self.assertEqual(self.handler.udp443.waiting, 0)
                transport.sendto(first, endpoints[0])
                self.assertEqual(await asyncio.wait_for(collector.queue.get(), 3), first)
        finally:
            transport.close()
            await asyncio.gather(*(tc.close_writer(writer) for writer in controls))

    async def test_udp_dns_ipv6_and_control_cleanup(self):
        reader, writer = await self.connect_socks(); await reader.readexactly(2)
        result, host, port = await self.request(reader,writer,3,'0.0.0.0',0)
        self.assertEqual(result,0)
        collector = DatagramCollector()
        transport, _ = await asyncio.get_running_loop().create_datagram_endpoint(
            lambda: collector, local_addr=('127.0.0.1',0), family=socket.AF_INET)
        try:
            for target in ('resolver.example','2001:db8::53','203.0.113.53'):
                packet = b'\0\0\0'+tc.encode_address(target,53)+b'fake-dns-payload'
                transport.sendto(packet,(host,port))
                self.assertEqual(await asyncio.wait_for(collector.queue.get(),3),packet)
            # Fragmented datagrams are explicitly unsupported and silently dropped.
            transport.sendto(b'\0\0\1'+tc.encode_address('resolver.example',53)+b'drop',(host,port))
            with self.assertRaises(asyncio.TimeoutError):
                await asyncio.wait_for(collector.queue.get(),.05)
            await tc.close_writer(writer)
            await asyncio.sleep(.1)
            self.assertEqual(len(self.handler.clients),0)
        finally: transport.close()


if __name__ == '__main__': unittest.main()
