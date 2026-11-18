"""Test the configured sing-box DNS through the phone. No TUN or system DNS edits."""
import argparse
import asyncio
from dataclasses import replace
import ipaddress
import json
from pathlib import Path
import socket

from prepare import Config, configuration, endpoint, wired_endpoint
from tunnel_client import SocksServer


async def answer(port, transport, name):
    task = await asyncio.create_subprocess_exec(
        '/usr/bin/dig', '@127.0.0.1', '-p', str(port), name, 'A',
        '+short', '+tries=1', '+time=7', '+tcp' if transport == 'TCP' else '+notcp',
        stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.DEVNULL)
    output, _ = await task.communicate()
    return task.returncode == 0 and any(is_ipv4(line) for line in output.splitlines())


def is_ipv4(line):
    try:
        return ipaddress.ip_address(line.decode('ascii')).version == 4
    except (UnicodeError, ValueError):
        return False


async def test_dns(engine, settings):
    # A high loopback port keeps macOS and every other app on their current DNS.
    with socket.socket() as reservation:
        reservation.bind(('127.0.0.1', 0))
        port = reservation.getsockname()[1]
    settings['inbounds'] = [{'type': 'direct', 'tag': 'probe', 'listen': '127.0.0.1',
                             'listen_port': port}]
    settings['route']['rules'] = [{'inbound': ['probe'], 'action': 'hijack-dns'}]
    settings['dns']['disable_cache'] = True
    proc = await asyncio.create_subprocess_exec(
        str(engine), 'run', '-c', 'stdin', stdin=asyncio.subprocess.PIPE,
        stdout=asyncio.subprocess.DEVNULL, stderr=asyncio.subprocess.DEVNULL)
    try:
        proc.stdin.write(json.dumps(settings).encode())
        await proc.stdin.drain()
        proc.stdin.close()
        for _ in range(40):
            if proc.returncode is not None:
                raise RuntimeError('sing-box no pudo abrir el listener local')
            try:
                _, writer = await asyncio.open_connection('127.0.0.1', port)
            except ConnectionRefusedError:
                await asyncio.sleep(0.05)
                continue
            writer.close()
            await writer.wait_closed()
            break
        else:
            raise RuntimeError('tiempo agotado abriendo el listener local')
        results = await asyncio.gather(answer(port, 'UDP', 'example.com.'),
                                       answer(port, 'TCP', 'example.org.'))
        print('DNS del motor por el iPhone (UDP / TCP):', *results, flush=True)
        return all(results) and proc.returncode is None
    finally:
        if proc.returncode is None:
            proc.terminate()
        await proc.wait()


async def https(config, port):
    def escape(value):
        if any(ord(char) < 32 for char in value):
            raise ValueError('Credencial SOCKS inválida')
        return value.replace('\\', '\\\\').replace('"', '\\"')
    auth = escape(config.socks_username + ':' + config.socks_password)
    curl = await asyncio.create_subprocess_exec(
        '/usr/bin/curl', '-q', '--config', '-', '--noproxy', '',
        '--proxy', f'socks5h://127.0.0.1:{port}', '--max-time', '15',
        '--silent', '--output', '/dev/null', '--write-out', '%{http_code} %{proxy_used}',
        'https://example.com/', stdin=asyncio.subprocess.PIPE,
        stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.DEVNULL)
    output, _ = await curl.communicate(f'proxy-user = "{auth}"\n'.encode())
    ok = curl.returncode == 0 and output == b'200 1'
    print(f'HTTPS por SOCKS: {ok} (curl {curl.returncode})', flush=True)
    return ok


async def main(args):
    config = Config.load(args.config)
    if args.endpoint:
        config = replace(config, server_host=endpoint(args.endpoint))
    if args.usb:
        config = replace(config, server_host=wired_endpoint(args.usb))
    print('Dirección del iPhone en esta sesión:', config.server_host, flush=True)
    relay = SocksServer(config)
    server = await asyncio.start_server(relay.handle, '127.0.0.1', args.serve or 0)
    try:
        port = server.sockets[0].getsockname()[1]
        ok = await https(config, port)
        dns_ok = await test_dns(args.engine, configuration(config, port))
        if ok and dns_ok and args.serve:
            print(f'Relay verificado en 127.0.0.1:{port}. Ctrl+C para cerrar.', flush=True)
            await server.serve_forever()
        return ok and dns_ok
    finally:
        server.close()
        await server.wait_closed()
        await relay.close()


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--engine', required=True, type=Path)
    parser.add_argument('--config', required=True, type=Path)
    transport = parser.add_mutually_exclusive_group()
    transport.add_argument('--endpoint')
    transport.add_argument('--usb', metavar='DEVICE', help='Consultar la dirección USB actual')
    parser.add_argument('--serve', type=int, metavar='PORT',
                        help='Tras verificar, mantener el relay local en este puerto')
    args = parser.parse_args()
    if args.serve is not None and not 1024 <= args.serve <= 65535:
        parser.error('El puerto del relay debe estar entre 1024 y 65535')
    try:
        raise SystemExit(0 if asyncio.run(main(args)) else 1)
    except KeyboardInterrupt:
        pass
