#!/usr/bin/env python3
"""Authenticated loopback SOCKS5 -> pinned TLS iPhone relay. No system network changes.

Python 3.10+. CONNECT and UDP ASSOCIATE; UDP is carried in framed TLS/TCP,
not a native VPN. Per-app SOCKS support is required. DNS names stay unresolved
on this client when applications send SOCKS domain names.
"""
from __future__ import annotations
import argparse
import asyncio
from dataclasses import dataclass
import hashlib
import hmac
import ipaddress
import json
import logging
import os
from pathlib import Path
import socket
import ssl
import stat
import struct
import time

LOG = logging.getLogger('cellular-tunnel')
MAX_FRAME = 65507
MAX_HEADER = 4096
MAX_CLIENTS = 128  # UDP control sockets and queued requests also count here.
LEGACY_PHONE_SESSIONS = 30  # Older iPhone builds accept 32 sessions.
MAX_PHONE_SESSIONS = 88
MAX_UDP_443_SESSIONS = 8  # Across all SOCKS associations.
UDP_443_PRESSURE_IDLE = 8
MAX_UDP_FLOWS = 8
MAX_UDP_QUEUE = 8
CONNECT_TIMEOUT = 20
HANDSHAKE_TIMEOUT = 15
DRAIN_TIMEOUT = 30
TCP_IDLE = 300
UDP_IDLE = 60


class ProtocolError(Exception):
    pass


@dataclass(frozen=True)
class Config:
    server_host: str
    server_port: int
    certificate_sha256: str
    token: str
    socks_username: str
    socks_password: str

    @classmethod
    def load(cls, path: Path) -> 'Config':
        # Do not expose pairing secrets to other users on the Mac.
        if os.name == 'posix' and stat.S_IMODE(path.stat().st_mode) & 0o077:
            raise ValueError('Configuration must be private: chmod 600 CONFIG_FILE')
        if path.stat().st_size > 16384:
            raise ValueError('Configuration too large')
        raw = json.loads(path.read_text(encoding='utf-8'))
        if not isinstance(raw, dict):
            raise ValueError('Configuration must be an object')
        address = ipaddress.ip_address(raw['server_host'])
        if (not address.is_private or address.is_unspecified or address.is_multicast
                or address.is_loopback):
            raise ValueError('server_host must be the private literal IP of your iPhone')
        port = raw.get('server_port', 49443)
        if type(port) is not int or not 1 <= port <= 65535:
            raise ValueError('Invalid server port')
        pin, token = raw['certificate_sha256'], raw['token']
        for name, value in [('certificate_sha256', pin), ('token', token)]:
            if not isinstance(value, str) or len(value) != 64:
                raise ValueError(f'{name} must be 64 hexadecimal characters')
            try:
                decoded = bytes.fromhex(value)
                if len(decoded) != 32: raise ValueError('Invalid hex length')
            except ValueError:
                raise ValueError(f'{name} must be hexadecimal') from None
        username, password = raw['socks_username'], raw['socks_password']
        if not isinstance(username, str) or not 1 <= len(username.encode('utf-8')) <= 255:
            raise ValueError('SOCKS username must be 1..255 UTF-8 bytes')
        if not isinstance(password, str) or not 16 <= len(password.encode('utf-8')) <= 255:
            raise ValueError('SOCKS password must be 16..255 UTF-8 bytes')
        return cls(str(address), port, pin.lower(), token, username, password)


def decode_address(data: bytes, offset: int = 0) -> tuple[str, int, int]:
    """Read ATYP+address+port. Return host, port, next offset. No DNS lookup."""
    try:
        kind = data[offset]
        offset += 1
        if kind == 1:
            end = offset + 4
            if len(data) < end: raise ProtocolError('Truncated IPv4 address')
            host = str(ipaddress.IPv4Address(data[offset:end]))
        elif kind == 4:
            end = offset + 16
            if len(data) < end: raise ProtocolError('Truncated IPv6 address')
            host = str(ipaddress.IPv6Address(data[offset:end]))
        elif kind == 3:
            length = data[offset]
            offset += 1
            end = offset + length
            if length == 0 or len(data) < end: raise ProtocolError('Invalid domain length')
            host = data[offset:end].decode('ascii')
            if len(host) > 253 or '\x00' in host or any(ord(c) < 33 or ord(c) > 126 for c in host):
                raise ProtocolError('Invalid domain')
        else:
            raise ProtocolError('Unsupported address type')
        if len(data) < end + 2: raise ProtocolError('Truncated port')
        port = struct.unpack('!H', data[end:end + 2])[0]
        return host, port, end + 2
    except (IndexError, UnicodeError, ValueError) as exc:
        raise ProtocolError('Invalid SOCKS address') from exc


def encode_address(host: str, port: int) -> bytes:
    if not 0 <= port <= 65535: raise ProtocolError('Invalid port')
    try:
        address = ipaddress.ip_address(host)
        encoded = bytes([1 if address.version == 4 else 4]) + address.packed
    except ValueError:
        domain = host.encode('idna')
        if not 1 <= len(domain) <= 253: raise ProtocolError('Invalid domain length')
        encoded = b'\x03' + bytes([len(domain)]) + domain
    return encoded + struct.pack('!H', port)


async def read_address(reader: asyncio.StreamReader, kind: int) -> tuple[str, int]:
    prefix = bytes([kind])
    if kind == 1:
        body = await reader.readexactly(6)
    elif kind == 4:
        body = await reader.readexactly(18)
    elif kind == 3:
        length = await reader.readexactly(1)
        body = length + await reader.readexactly(length[0] + 2)
    else:
        raise ProtocolError('Unsupported address type')
    host, port, _ = decode_address(prefix + body)
    return host, port


async def drain(writer: asyncio.StreamWriter):
    await asyncio.wait_for(writer.drain(), DRAIN_TIMEOUT)


async def close_writer(writer: asyncio.StreamWriter | None):
    if writer is None: return
    writer.close()
    try:
        await asyncio.wait_for(writer.wait_closed(), 3)
    except (Exception, asyncio.CancelledError):
        # Abort rather than hang on TLS close_notify from a vanished phone.
        writer.transport.abort()


async def send_frame(writer: asyncio.StreamWriter, kind: bytes, payload: bytes = b''):
    if kind not in (b'D', b'F', b'E') or len(payload) > MAX_FRAME:
        raise ProtocolError('Invalid frame')
    if kind == b'F' and payload or kind == b'E' and len(payload) > MAX_HEADER:
        raise ProtocolError('Invalid control frame')
    writer.write(kind + struct.pack('!I', len(payload)) + payload)
    await drain(writer)


async def read_frame(reader: asyncio.StreamReader) -> tuple[bytes, bytes]:
    header = await reader.readexactly(5)
    kind, length = header[:1], struct.unpack('!I', header[1:])[0]
    if kind not in (b'D', b'F', b'E') or length > MAX_FRAME:
        raise ProtocolError('Invalid frame')
    if kind == b'F' and length or kind == b'E' and length > MAX_HEADER:
        raise ProtocolError('Invalid control frame')
    return kind, await reader.readexactly(length)


async def open_tunnel(config: Config, transport: str, host: str, port: int, slots=None):
    """Certificate pin is the trust anchor, verified before sending token or target."""
    if transport not in ('tcp', 'udp') or not 1 <= port <= 65535:
        raise ProtocolError('Invalid tunnel destination')
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE  # Exact SHA256 DER pin checked below.
    writer = None
    try:
        async with _timeout(CONNECT_TIMEOUT):
            reader, writer = await asyncio.open_connection(
                config.server_host, config.server_port, ssl=context,
                server_hostname=None, limit=MAX_FRAME + MAX_HEADER)
            tls = writer.get_extra_info('ssl_object')
            der = tls.getpeercert(binary_form=True) if tls else None
            if not der or not hmac.compare_digest(hashlib.sha256(der).hexdigest(), config.certificate_sha256):
                raise ProtocolError('iPhone certificate pin mismatch')
            header = json.dumps({'v': 1, 'token': config.token, 'transport': transport,
                                 'host': host, 'port': port}, separators=(',', ':')).encode() + b'\n'
            if len(header) > MAX_HEADER: raise ProtocolError('Header too large')
            writer.write(header)
            await drain(writer)
            response = await reader.readuntil(b'\n')
            if len(response) > MAX_HEADER: raise ProtocolError('Oversized server response')
            reply = json.loads(response)
            if not isinstance(reply, dict) or reply.get('ok') is not True:
                raise ProtocolError('iPhone refused tunnel')
            if slots is not None:
                await slots.configure(reply.get('max_sessions'))
            return reader, writer
    except BaseException:
        await close_writer(writer)
        raise


class _timeout:
    """Python 3.10 compatible task timeout context."""
    def __init__(self, delay): self.delay = delay; self.expired = False
    async def __aenter__(self):
        self.task = asyncio.current_task()
        def expire():
            self.expired = True
            self.task.cancel()
        self.timer = asyncio.get_running_loop().call_later(self.delay, expire)
    async def __aexit__(self, exc_type, exc, tb):
        self.timer.cancel()
        if exc_type is asyncio.CancelledError and self.expired:
            raise asyncio.TimeoutError() from None
        return False


async def authenticate(reader, writer, config):
    version, count = await reader.readexactly(2)
    if version != 5 or count == 0: raise ProtocolError('Invalid SOCKS greeting')
    methods = await reader.readexactly(count)
    if 2 not in methods:
        writer.write(b'\x05\xff'); await drain(writer)
        raise ProtocolError('Username/password authentication required')
    writer.write(b'\x05\x02'); await drain(writer)
    version, length = await reader.readexactly(2)
    if version != 1 or length == 0: raise ProtocolError('Invalid authentication')
    username = await reader.readexactly(length)
    length = (await reader.readexactly(1))[0]
    password = await reader.readexactly(length)
    valid = hmac.compare_digest(username, config.socks_username.encode())
    valid &= hmac.compare_digest(password, config.socks_password.encode())
    writer.write(b'\x01' + (b'\x00' if valid else b'\x01'))
    await drain(writer)
    if not valid: raise ProtocolError('Authentication failed')


async def socks_reply(writer, code, host='127.0.0.1', port=0):
    writer.write(bytes([5, code, 0]) + encode_address(host, port))
    await drain(writer)


async def relay_tcp(reader, writer, remote_reader, remote_writer, trace=None, flow=None):
    last_activity = time.monotonic()
    async def outbound():
        nonlocal last_activity
        while True:
            data = await reader.read(32768)
            last_activity = time.monotonic()
            if not data:
                if trace: trace.update(flow, 'FIN-local')
                await send_frame(remote_writer, b'F')
                return
            if trace: trace.update(flow, direction='up', size=len(data))
            await send_frame(remote_writer, b'D', data)
    async def inbound():
        nonlocal last_activity
        while True:
            kind, data = await read_frame(remote_reader)
            last_activity = time.monotonic()
            if kind == b'E': raise ProtocolError('Remote tunnel failed')
            if kind == b'F':
                if trace: trace.update(flow, 'FIN-remoto')
                if writer.can_write_eof():
                    writer.write_eof()
                    await drain(writer)
                return
            if trace: trace.update(flow, direction='down', size=len(data))
            writer.write(data)
            await drain(writer)
    async def watchdog():
        while True:
            await asyncio.sleep(min(10, TCP_IDLE))
            if time.monotonic() - last_activity >= TCP_IDLE:
                raise asyncio.TimeoutError('Idle tunnel')
    workers = [asyncio.create_task(outbound()), asyncio.create_task(inbound())]
    pipes = asyncio.gather(*workers)
    timer = asyncio.create_task(watchdog())
    try:
        done, _ = await asyncio.wait([pipes, timer], return_when=asyncio.FIRST_COMPLETED)
        for task in done: await task
    finally:
        for worker in workers: worker.cancel()
        pipes.cancel(); timer.cancel()
        await asyncio.gather(*workers, pipes, timer, return_exceptions=True)


class PhoneSlots:
    def __init__(self, ceiling=MAX_PHONE_SESSIONS):
        self.ceiling = ceiling
        self.limit = min(LEGACY_PHONE_SESSIONS, ceiling)
        self.used = 0
        self.changed = asyncio.Condition()

    async def configure(self, advertised):
        limit = LEGACY_PHONE_SESSIONS
        if type(advertised) is int and advertised >= 3:
            limit = advertised - 2  # Allow the phone to finish closing older TLS sessions.
        limit = min(self.ceiling, limit)
        async with self.changed:
            if limit != self.limit:
                self.limit = limit
                self.changed.notify_all()

    async def acquire(self):
        async with self.changed:
            await self.changed.wait_for(lambda: self.used < self.limit)
            self.used += 1

    async def release(self):
        async with self.changed:
            self.used -= 1
            self.changed.notify_all()


class UDP443Budget:
    def __init__(self):
        self.slots = asyncio.BoundedSemaphore(MAX_UDP_443_SESSIONS)
        self.waiting = 0

    async def acquire(self):
        self.waiting += 1
        try:
            await self.slots.acquire()
        finally:
            self.waiting -= 1

    def release(self):
        self.slots.release()


class UDPFlow:
    def __init__(self, owner, host, port, address_bytes):
        self.owner, self.host, self.port, self.address_bytes = owner, host, port, address_bytes
        self.queue = asyncio.Queue(MAX_UDP_QUEUE)
        self.last_activity = time.monotonic()
        self.task = asyncio.create_task(self.run())
        self.writer = None
    async def run(self):
        tasks = []
        acquired = False
        limited = False
        flow = None
        trace = self.owner.trace
        try:
            async with _timeout(CONNECT_TIMEOUT):
                if self.port == 443:
                    await self.owner.udp443.acquire()
                    limited = True
                await self.owner.phone_slots.acquire()
                acquired = True
            if trace: flow = trace.begin('UDP', self.host, self.port)
            reader, self.writer = await open_tunnel(self.owner.config, 'udp', self.host, self.port,
                                                    self.owner.phone_slots)
            if trace: trace.update(flow, 'abierto')
            async def sender():
                while True:
                    data = await self.queue.get()
                    if trace: trace.update(flow, direction='up', size=len(data))
                    await send_frame(self.writer, b'D', data)
                    self.last_activity = time.monotonic()
            async def receiver():
                while True:
                    kind, data = await read_frame(reader)
                    if kind != b'D': return
                    if trace: trace.update(flow, direction='down', size=len(data))
                    self.last_activity = time.monotonic()
                    if self.owner.client_address is not None and len(data) + len(self.address_bytes) + 3 <= 65507:
                        self.owner.transport.sendto(b'\0\0\0' + self.address_bytes + data, self.owner.client_address)
            async def idle():
                while True:
                    await asyncio.sleep(min(2, UDP_IDLE))
                    limit = UDP_443_PRESSURE_IDLE if limited and self.owner.udp443.waiting else UDP_IDLE
                    if self.queue.empty() and time.monotonic() - self.last_activity >= limit:
                        return
            tasks = [asyncio.create_task(sender()), asyncio.create_task(receiver()), asyncio.create_task(idle())]
            done, _ = await asyncio.wait(tasks, return_when=asyncio.FIRST_COMPLETED)
            for task in done: await task
        except asyncio.CancelledError:
            raise
        except Exception:
            LOG.debug('UDP flow closed')
        finally:
            for task in tasks: task.cancel()
            await asyncio.gather(*tasks, return_exceptions=True)
            await close_writer(self.writer)
            if acquired:
                await self.owner.phone_slots.release()
                if trace: trace.end(flow)
            if limited:
                self.owner.udp443.release()
            if self.owner.flows.get((self.host, self.port)) is self:
                self.owner.flows.pop((self.host, self.port), None)
    def enqueue(self, data):
        try: self.queue.put_nowait(data)
        except asyncio.QueueFull: pass  # Bounded UDP loss; never grow without limit.


class UDPAssociation(asyncio.DatagramProtocol):
    def __init__(self, config, requested_port, phone_slots, udp443, trace=None):
        self.config = config
        self.trace = trace
        self.phone_slots = phone_slots
        self.udp443 = udp443
        self.requested_port = requested_port
        self.client_address = None
        self.transport = None
        self.flows = {}
        self.closed = False
    def connection_made(self, transport): self.transport = transport
    def datagram_received(self, data, addr):
        if self.closed or len(data) > 65507: return
        try:
            if not ipaddress.ip_address(addr[0]).is_loopback: return
            if self.requested_port and addr[1] != self.requested_port: return
            if self.client_address is not None and addr != self.client_address: return
            if len(data) < 4 or data[:3] != b'\0\0\0': return  # Drop reserved/FRAG.
            host, port, offset = decode_address(data, 3)
            if port == 0: return
            if self.client_address is None: self.client_address = addr
            key = (host, port)
            flow = self.flows.get(key)
            if flow is None:
                if len(self.flows) >= MAX_UDP_FLOWS: return
                flow = UDPFlow(self, host, port, data[3:offset])
                self.flows[key] = flow
            flow.enqueue(data[offset:])
        except (ProtocolError, ValueError): return
    def error_received(self, exc): LOG.debug('Local UDP transport error')
    async def close(self):
        self.closed = True
        if self.transport: self.transport.close()
        tasks = [flow.task for flow in self.flows.values()]
        for task in tasks: task.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)
        self.flows.clear()


class SocksServer:
    def __init__(self, config, trace=None):
        self.config = config
        self.trace = trace
        self.phone_slots = PhoneSlots()
        self.udp443 = UDP443Budget()
        self.clients = set()
    async def handle(self, reader, writer):
        if len(self.clients) >= MAX_CLIENTS:
            await close_writer(writer)
            return
        task = asyncio.current_task()
        self.clients.add(task)
        remote_writer, association = None, None
        reply_sent = False
        acquired = False
        request_parsed = False
        flow = None
        try:
            async with _timeout(HANDSHAKE_TIMEOUT):
                await authenticate(reader, writer, self.config)
                version, command, reserved, kind = await reader.readexactly(4)
                if version != 5 or reserved != 0: raise ProtocolError('Invalid request')
                host, port = await read_address(reader, kind)
                request_parsed = True
            if command == 1:
                if port == 0: raise ProtocolError('Invalid port')
                await asyncio.wait_for(self.phone_slots.acquire(), CONNECT_TIMEOUT)
                acquired = True
                if self.trace: flow = self.trace.begin('TCP', host, port)
                remote_reader, remote_writer = await open_tunnel(self.config, 'tcp', host, port, self.phone_slots)
                if self.trace: self.trace.update(flow, 'abierto')
                await socks_reply(writer, 0); reply_sent = True
                await relay_tcp(reader, writer, remote_reader, remote_writer, self.trace, flow)
            elif command == 3:
                try: address = ipaddress.ip_address(host)
                except ValueError: raise ProtocolError('UDP bind address must be IP') from None
                if not (address.is_unspecified or address.is_loopback):
                    raise ProtocolError('UDP client must be local')
                # Public UDP control endpoint is deliberately IPv4 loopback only;
                # remote IPv6 targets are supported in SOCKS datagram headers.
                association = UDPAssociation(self.config, port, self.phone_slots, self.udp443, self.trace)
                transport, _ = await asyncio.get_running_loop().create_datagram_endpoint(
                    lambda: association, local_addr=('127.0.0.1', 0), family=socket.AF_INET)
                await socks_reply(writer, 0, '127.0.0.1', transport.get_extra_info('sockname')[1])
                reply_sent = True
                # Closing the authenticated TCP control closes every UDP flow.
                while await reader.read(1024):
                    raise ProtocolError('Unexpected UDP control data')
            else:
                await socks_reply(writer, 7); reply_sent = True
        except asyncio.CancelledError:
            raise
        except Exception:
            if request_parsed and not reply_sent:
                try: await socks_reply(writer, 1)
                except Exception: pass
            LOG.debug('SOCKS connection closed')
        finally:
            if association: await association.close()
            await close_writer(remote_writer)
            if acquired:
                await self.phone_slots.release()
                if self.trace: self.trace.end(flow)
            await close_writer(writer)
            self.clients.discard(task)
    async def close(self):
        tasks = list(self.clients)
        for task in tasks: task.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)


async def serve(config, port):
    handler = SocksServer(config)
    server = await asyncio.start_server(handler.handle, '127.0.0.1', port, limit=MAX_FRAME + MAX_HEADER)
    LOG.warning('SOCKS5 listening on 127.0.0.1:%d; authentication required. No system settings changed.', port)
    try:
        async with server: await server.serve_forever()
    finally: await handler.close()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--config', type=Path, required=True)
    parser.add_argument('--port', type=int, default=1080)
    parser.add_argument('--verbose', action='store_true', help='Generic connection diagnostics, no secrets/targets')
    args = parser.parse_args()
    logging.basicConfig(level=logging.DEBUG if args.verbose else logging.WARNING, format='%(message)s')
    if not 1024 <= args.port <= 65535: parser.error('--port must be 1024..65535')
    try:
        config = Config.load(args.config)
        asyncio.run(serve(config, args.port))
    except KeyboardInterrupt:
        pass
    except (OSError, ValueError, KeyError) as exc:
        parser.exit(1, f'Cannot start: {exc}\n')


if __name__ == '__main__': main()
