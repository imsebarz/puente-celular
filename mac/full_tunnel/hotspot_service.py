"""launchd runs one session at a time. Only the unprivileged relay reads the pairing."""
import asyncio
from dataclasses import replace
import hmac
import json
import os
from pathlib import Path
import pwd
import secrets
import select
import signal
import socket
import subprocess
import sys
import time
from types import SimpleNamespace

# Isolated Python (-I -S -B). The installer makes this entire tree root-owned.
HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
from prepare import Config, configuration
from probe import https
from temporary_test import DNS, native_dns, route, run, run_session, stop
from tunnel_client import SocksServer
from flow_trace import FlowTrace

ROOT = HERE.parent.parent


def on_hotspot(profile):
    return (os.stat('/dev/console').st_uid == profile['uid']
            and run('/usr/sbin/ipconfig', 'getoption', profile['wifi'], 'router').strip() == profile['phone']
            and route(profile['phone']).get('interface') == profile['wifi'])


def vpn_clear():
    services = run('/usr/sbin/scutil', '--nc', 'list')
    return bool(services) and '(Connected)' not in services and '(Connecting)' not in services


async def serve_phone(profile, fd, notify_fd):
    if os.getuid() != profile['uid'] or os.getuid() == 0:
        raise RuntimeError('El relay debe ejecutarse como el usuario registrado')
    config = Config.load(Path(profile['config']))
    if not hmac.compare_digest(config.certificate_sha256, profile['pin']):
        raise RuntimeError('Cambió la identidad del iPhone')
    credentials = json.loads(sys.stdin.buffer.readline(1024))
    config = replace(config, server_host=profile['phone'], socks_username=credentials[0],
                     socks_password=credentials[1])
    trace = FlowTrace(profile['config'])
    relay = SocksServer(config, trace if trace.file else None)
    server = await asyncio.start_server(relay.handle, sock=socket.socket(fileno=fd))
    try:
        if not await https(config, server.sockets[0].getsockname()[1]):
            return
        os.write(notify_fd, b'1')
        os.close(notify_fd)
        await server.serve_forever()
    finally:
        server.close()
        await server.wait_closed()
        await relay.close()


def web_works(url):
    return run('/usr/bin/curl', '-q', '-4', '--noproxy', '*', '--max-time', '5',
               '-s', '-o', '/dev/null', '-w', '%{http_code}', url) == '200'


def activate(profile):
    if not on_hotspot(profile) or not vpn_clear() or route('1.1.1.1').get('interface', '').startswith('utun'):
        return
    user = pwd.getpwuid(profile['uid'])
    if user.pw_uid == 0:
        raise RuntimeError('El relay requiere un usuario estándar')
    username, password = 'puente', secrets.token_urlsafe(32)
    helper = ROOT / 'session-dns'
    args = SimpleNamespace(endpoint=profile['phone'], full=True, helper=helper,
                           seconds=0, engine=ROOT / 'sing-box')
    # Reserve the loopback endpoint until the engine has stopped. Hand the same
    # socket to the relay after dropping privileges; no other listener can replace it.
    with socket.socket() as listener:
        listener.bind(('127.0.0.1', 0))
        listener.listen()
        port = listener.getsockname()[1]
        reader, writer = os.pipe()
        child = None
        try:
            child = subprocess.Popen(
                ['/usr/bin/python3', '-I', '-S', '-B', __file__, 'relay',
                 str(listener.fileno()), str(writer)],
                user=user.pw_uid, group=user.pw_gid, extra_groups=[],
                pass_fds=(listener.fileno(), writer), stdin=subprocess.PIPE,
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, cwd='/')
            os.close(writer)
            writer = None
            child.stdin.write(json.dumps([username, password]).encode() + b'\n')
            child.stdin.close()
            if not select.select([reader], [], [], 18)[0] or os.read(reader, 1) != b'1':
                return
            if not on_hotspot(profile):
                return
            local = Config(profile['phone'], 49443, profile['pin'], '', username, password)
            settings = configuration(local, port)
            next_https = 0

            def healthy(tun):
                nonlocal next_https
                if (child.poll() is not None or not on_hotspot(profile) or not vpn_clear() or native_dns() != [DNS]
                        or route('1.1.1.1').get('interface') != tun or route(DNS).get('interface') != tun):
                    return False
                if time.monotonic() < next_https:
                    return True
                next_https = time.monotonic() + 30
                return web_works('https://example.org/') or web_works('https://www.apple.com/')

            run_session(args, settings, health_check=healthy)
        finally:
            os.close(reader)
            if writer is not None:
                os.close(writer)
            stop(child)


def terminate(*_):
    raise SystemExit(0)


if __name__ == '__main__':
    profile = json.loads((ROOT / 'hotspot.json').read_bytes())
    if len(sys.argv) == 4 and sys.argv[1] == 'relay':
        asyncio.run(serve_phone(profile, int(sys.argv[2]), int(sys.argv[3])))
    elif len(sys.argv) == 1 and os.geteuid() == 0:
        signal.signal(signal.SIGTERM, terminate)
        signal.signal(signal.SIGHUP, terminate)
        try:
            activate(profile)
        except (OSError, ValueError, RuntimeError, subprocess.SubprocessError) as error:
            print('Sesión cerrada:', type(error).__name__, flush=True)
            time.sleep(60)
    else:
        raise SystemExit('Ejecutar mediante launchd')
