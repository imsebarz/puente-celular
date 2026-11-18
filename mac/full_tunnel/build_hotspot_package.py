"""Build the local macOS launchd package as the user. No installation or networking."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import plistlib
import re
import shutil
import subprocess
import tempfile

from prepare import Config, endpoint

LABEL = 'co.puentecelular.hotspot'
INSTALL = Path('/Library/PrivilegedHelperTools') / LABEL
# Executable from the vendor's v1.14.4 Darwin arm64 release archive.
ENGINE_SHA256 = '6546126c1759683fe85798da92409215d53c50e0f2b346b4f74a61babc8dbec2'


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--config', type=Path, required=True)
    parser.add_argument('--engine', type=Path, required=True)
    parser.add_argument('--wifi', required=True)
    parser.add_argument('--phone', required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    if os.geteuid() == 0 or not re.fullmatch(r'en[0-9]+', args.wifi):
        parser.error('Construir como usuario con la interfaz Wi-Fi física')
    source = Path(__file__).resolve().parent
    pairing = Config.load(args.config)
    with tempfile.TemporaryDirectory(prefix='puente-pkg-') as scratch:
        target = Path(scratch) / 'root'
        modules = target / 'mac' / 'full_tunnel'
        modules.mkdir(parents=True)
        shutil.copyfile(args.engine, target / 'sing-box')
        if hashlib.sha256((target / 'sing-box').read_bytes()).hexdigest() != ENGINE_SHA256:
            raise ValueError('El motor no coincide con la versión verificada')
        shutil.copyfile(source.parent / 'tunnel_client.py', modules.parent / 'tunnel_client.py')
        shutil.copyfile(source.parent / 'flow_trace.py', modules.parent / 'flow_trace.py')
        for name in ('hotspot_service.py', 'temporary_test.py', 'probe.py', 'prepare.py'):
            shutil.copyfile(source / name, modules / name)
        subprocess.run(['/usr/bin/swiftc', '-module-cache-path', str(Path(scratch) / 'swift-cache'),
                        str(source / 'SessionDNS.swift'), '-o', str(target / 'session-dns')], check=True)
        profile = {'uid': os.getuid(), 'wifi': args.wifi, 'phone': endpoint(args.phone),
                   'config': str(args.config.resolve()), 'pin': pairing.certificate_sha256}
        (target / 'hotspot.json').write_text(json.dumps(profile))
        plist = {
            'Label': LABEL,
            'ProgramArguments': ['/usr/bin/python3', '-I', '-S', '-B',
                                 str(INSTALL / 'mac/full_tunnel/hotspot_service.py')],
            'RunAtLoad': True, 'StartInterval': 15, 'ExitTimeOut': 20,
            'WorkingDirectory': '/', 'Umask': 0o077,
            'EnvironmentVariables': {'PATH': '/usr/bin:/bin:/usr/sbin:/sbin'},
        }
        (target / (LABEL + '.plist')).write_bytes(plistlib.dumps(plist))
        target.chmod(0o755)
        for path in target.rglob('*'):
            path.chmod(0o755 if path.is_dir() or path.name in ('sing-box', 'session-dns') else 0o644)
        subprocess.run(['/usr/bin/pkgbuild', '--root', str(target), '--ownership', 'recommended',
                        '--identifier', LABEL, '--version', '1.4', '--install-location', str(INSTALL),
                        str(args.output.resolve())], check=True)


if __name__ == '__main__':
    main()
