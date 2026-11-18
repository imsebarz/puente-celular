#!/usr/bin/env python3
"""Check live per-device revocation on an iPhone using two private client profiles."""
import argparse
import asyncio
import ipaddress
from dataclasses import replace
from pathlib import Path
import secrets
import struct
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'mac'))
from tunnel_client import Config, ProtocolError, close_writer, open_tunnel, read_frame, send_frame


async def dns_exchange(stream, transport):
    reader, writer = stream
    tag = secrets.token_bytes(2)
    query = tag + bytes.fromhex('01000001000000000000') + b'\x07example\x03org\x00\x00\x01\x00\x01'
    prefix = struct.pack('!H', len(query)) if transport == 'tcp' else b''
    await send_frame(writer, b'D', prefix + query)
    response = bytearray()
    while True:
        kind, part = await read_frame(reader)
        if kind != b'D':
            raise ConnectionError('El flujo se cerró')
        response.extend(part)
        if transport == 'udp':
            break
        if len(response) >= 2 and len(response) >= 2 + int.from_bytes(response[:2], 'big'):
            response = response[2:]
            break
    if len(response) < 12 or response[:2] != tag or response[3] & 15 or not int.from_bytes(response[6:8], 'big'):
        raise RuntimeError('El resolver no respondió a la consulta')


async def rejected(config, transport):
    try:
        _, writer = await open_tunnel(config, transport, '1.1.1.1', 53)
    except ProtocolError as error:
        if str(error) == 'iPhone refused tunnel':
            return True
        raise
    await close_writer(writer)
    return False


async def check(args):
    remove, keep = (Config.load(path) for path in (args.revoke, args.keep))
    if remove.token == keep.token or remove.certificate_sha256 != keep.certificate_sha256:
        raise ValueError('Se requieren dos credenciales diferentes del mismo iPhone')
    if args.endpoint:
        address = ipaddress.ip_address(args.endpoint)
        if not address.is_private or address.is_loopback or address.is_unspecified or address.is_multicast:
            raise ValueError('Usa la dirección privada del iPhone')
        remove, keep = (replace(config, server_host=args.endpoint) for config in (remove, keep))
    if (remove.server_host, remove.server_port) != (keep.server_host, keep.server_port):
        raise ValueError('Se requiere el mismo endpoint')
    streams = {}
    kinds = ('tcp', 'udp')
    try:
        for label, config in [('retirar', remove), ('conservar', keep)]:
            for kind in kinds:
                stream = await open_tunnel(config, kind, '1.1.1.1', 53)
                streams[label, kind] = stream
                await asyncio.wait_for(dns_exchange(stream, kind), 7)
        print('CUATRO FLUJOS ACTIVOS. Quita solo el acceso del perfil de prueba.', flush=True)
        deadline = asyncio.get_running_loop().time() + args.seconds
        while asyncio.get_running_loop().time() < deadline:
            for kind in kinds:
                await asyncio.wait_for(dns_exchange(streams['conservar', kind], kind), 7)
            if await rejected(remove, 'tcp'):
                break
            # Keep the candidate streams alive until the explicit denial is observed.
            for kind in kinds:
                try:
                    await asyncio.wait_for(dns_exchange(streams['retirar', kind], kind), 7)
                except (ConnectionError, asyncio.IncompleteReadError):
                    pass
            await asyncio.sleep(1)
        else:
            raise TimeoutError('No se observó la revocación durante la prueba')
        for kind in kinds:
            reader, _ = streams['retirar', kind]
            try:
                data = await asyncio.wait_for(reader.read(1), 5)
            except (ConnectionError, asyncio.IncompleteReadError):
                data = b''
            if data or not await rejected(remove, kind):
                raise RuntimeError('El dispositivo retirado conserva acceso')
            await asyncio.wait_for(dns_exchange(streams['conservar', kind], kind), 7)
            new_stream = await open_tunnel(keep, kind, '1.1.1.1', 53)
            try:
                await asyncio.wait_for(dns_exchange(new_stream, kind), 7)
            finally:
                await close_writer(new_stream[1])
        print('PASS. TCP y UDP cerrados y denegados al perfil retirado. '
              'El otro conservó sus flujos y abrió conexiones nuevas.', flush=True)
    finally:
        await asyncio.gather(*(close_writer(writer) for _, writer in streams.values()))


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--revoke', required=True, type=Path)
    parser.add_argument('--keep', required=True, type=Path)
    parser.add_argument('--endpoint', help='IPv4 del hotspot si el perfil inicial se creó para USB')
    parser.add_argument('--seconds', type=int, default=180)
    asyncio.run(check(parser.parse_args()))
