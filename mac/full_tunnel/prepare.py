#!/usr/bin/env python3
"""Prepare ONLY. Never installs software or changes network settings.

Targets sing-box >=1.14 configuration API; engine validation still required.
"""
import argparse
from dataclasses import asdict, replace
import ipaddress
import json
import os
from pathlib import Path
import subprocess
import sys
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from tunnel_client import Config


def endpoint(value):
    address = ipaddress.ip_address(value)
    if not address.is_private or address.is_loopback or address.is_multicast or address.is_unspecified or address.is_link_local:
        raise ValueError('Use a private literal endpoint, not a link-local, public or loopback address')
    return str(address)


def wired_endpoint(device):
    result = subprocess.run(
        ['/usr/bin/xcrun', 'devicectl', 'device', 'info', 'details', '--device', device,
         '--timeout', '8', '--json-output', '-', '--quiet'],
        capture_output=True, check=True, timeout=12)
    connection = json.loads(result.stdout)['result']['connectionProperties']
    if connection.get('transportType') != 'wired' or connection.get('tunnelState') != 'connected':
        raise ValueError('CoreDevice no confirmó un iPhone conectado por cable')
    return endpoint(connection['tunnelIPAddress'])


def configuration(config, socks_port=1080):
    if type(socks_port) is not int or not 1 <= socks_port <= 65535:
        raise ValueError('Invalid SOCKS port')
    phone = ipaddress.ip_address(endpoint(config.server_host))
    return {
        'log': {'level': 'warn', 'timestamp': True},
        'dns': {
            'servers': [{'type': 'tls', 'tag': 'cellular-dns', 'server': '1.1.1.1', 'server_port': 853,
                         'detour': 'phone', 'tls': {'enabled': True, 'server_name': 'cloudflare-dns.com'}}],
            'final': 'cellular-dns', 'strategy': 'ipv4_only'},
        'inbounds': [{'type': 'tun', 'tag': 'mac-tun',
                      'address': ['172.30.255.1/30', 'fdce:11ab:1e00::1/126'],
                      'mtu': 1400, 'auto_route': True, 'dns_mode': 'hijack',
                      'route_exclude_address': [str(phone) + ('/32' if phone.version == 4 else '/128')]}],
        'outbounds': [{'type': 'socks', 'tag': 'phone', 'server': '127.0.0.1',
                       'server_port': socks_port, 'version': '5',
                       'username': config.socks_username, 'password': config.socks_password}],
        'route': {'rules': [{'port': 53, 'action': 'hijack-dns'}], 'final': 'phone'}
    }


def write_private(path, data):
    # Exclusive creation prevents following symlinks or overwriting secrets.
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, 'w') as handle:
        json.dump(data, handle, indent=2)
        handle.write('\n')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--config', required=True, type=Path)
    parser.add_argument('--endpoint', help='Verified iPhone USB or hotspot private address')
    parser.add_argument('--output-dir', required=True, type=Path)
    parser.add_argument('--socks-port', type=int, default=1080)
    args = parser.parse_args()
    config = Config.load(args.config)
    if args.endpoint:
        config = replace(config, server_host=endpoint(args.endpoint))
    full = configuration(config, args.socks_port)
    args.output_dir.mkdir(mode=0o700, parents=False, exist_ok=False)
    write_private(args.output_dir / 'relay.json', asdict(config))
    write_private(args.output_dir / 'sing-box.json', full)
    print('Prepared private configuration only. No network settings changed.')
    print('Requires approved sing-box installation, schema check, route/DNS snapshot and activation.')

if __name__ == '__main__':
    main()
