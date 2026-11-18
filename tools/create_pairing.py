#!/usr/bin/env python3
"""Create fresh private pairing files. Does not install identities or alter network settings."""
import argparse
import base64
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import secrets
import shutil
import subprocess
import tempfile


def private_write(path, data):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, 'wb') as handle:
        handle.write(data)


def generate(output, server_host, server_port=49443):
    address = ipaddress.ip_address(server_host)
    if not address.is_private or address.is_unspecified or address.is_loopback or address.is_multicast:
        raise ValueError('server-host debe ser la IP privada real del iPhone.')
    if not 1 <= server_port <= 65535:
        raise ValueError('Puerto inválido.')
    openssl = shutil.which('openssl')
    if not openssl:
        raise RuntimeError('Se requiere openssl. No se instala automáticamente.')
    destination = Path(output).expanduser()
    # Refuse overwrite rather than accidentally rotate an active pairing.
    destination.mkdir(mode=0o700, parents=False, exist_ok=False)
    os.chmod(destination, 0o700)
    try:
        with tempfile.TemporaryDirectory(prefix='cellular-pairing-') as temporary:
            work = Path(temporary)
            password = secrets.token_urlsafe(32)
            private_write(work / 'password', password.encode())
            def execute(*arguments):
                subprocess.run([openssl, *arguments], cwd=work, check=True,
                               stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            execute('req', '-x509', '-newkey', 'rsa:3072',
                    '-nodes', '-keyout', 'key.pem', '-out', 'certificate.pem', '-days', '30',
                    '-subj', '/CN=Private Cellular Tunnel', '-sha256')
            execute('x509', '-in', 'certificate.pem', '-outform', 'DER', '-out', 'certificate.der')
            execute('pkcs12', '-export', '-inkey', 'key.pem', '-in', 'certificate.pem',
                    '-out', 'identity.p12', '-passout', 'file:password',
                    '-keypbe', 'PBE-SHA1-3DES', '-certpbe', 'PBE-SHA1-3DES', '-macalg', 'sha1')
            token = secrets.token_hex(32)
            fingerprint = hashlib.sha256((work / 'certificate.der').read_bytes()).hexdigest()
            server = {
                'v': 1, 'server_port': server_port,
                'pkcs12_base64': base64.b64encode((work / 'identity.p12').read_bytes()).decode(),
                'pkcs12_password': password, 'token': token, 'certificate_sha256': fingerprint,
            }
            client = {
                'server_host': str(address), 'server_port': server_port,
                'certificate_sha256': fingerprint, 'token': token,
                'socks_username': 'local', 'socks_password': secrets.token_urlsafe(32),
            }
            private_write(destination / 'iphone-pairing.json', (json.dumps(server, indent=2) + '\n').encode())
            private_write(destination / 'mac-config.json', (json.dumps(client, indent=2) + '\n').encode())
    except Exception:
        # Only remove the directory this call just created; it cannot preexist.
        shutil.rmtree(destination)
        raise
    return destination


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--server-host', required=True)
    parser.add_argument('--server-port', type=int, default=49443)
    parser.add_argument('--output', required=True, help='Directorio nuevo para secretos, fuera del repositorio')
    args = parser.parse_args()
    old_umask = os.umask(0o077)
    try:
        output = generate(args.output, args.server_host, args.server_port)
    except (ValueError, OSError, RuntimeError, subprocess.CalledProcessError) as error:
        print(f'No se generó emparejamiento: {type(error).__name__}. Revisa argumentos y disponibilidad de OpenSSL.')
        return 1
    finally:
        os.umask(old_umask)
    print(f'Archivos privados creados en {output}. No los publiques ni los adjuntes a chats.')
    print('Importa iphone-pairing.json en la app iPhone por un medio privado; guarda mac-config.json solo en tu Mac.')
    print('La clave privada va dentro del archivo iPhone. Elimina copias transferidas cuando termines la importación.')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
