"""Bounded macOS route test. Default scope is one DNS host, with native DNS untouched."""
import argparse
import asyncio
import ipaddress
import json
import os
from pathlib import Path
import re
import signal
import subprocess
import time

from prepare import endpoint
from probe import test_dns, is_ipv4

DNS = '172.30.255.2'


def run(*args, timeout=8):
    proc = subprocess.run(args, capture_output=True, timeout=timeout)
    return proc.stdout.decode(errors='replace') if proc.returncode == 0 else ''


def route(address):
    af = '-inet6' if ':' in address else '-inet'
    output = run('/sbin/route', '-n', 'get', af, address)
    return dict(re.findall(r'^\s*(interface|destination|gateway):\s*(\S+)', output, re.M))


def native_dns():
    output = run('/usr/sbin/scutil', '--dns').partition('DNS configuration (for scoped queries)')[0]
    first = output.partition('resolver #1')[2].partition('resolver #2')[0]
    return re.findall(r'nameserver\[\d+\]\s*:\s*(\S+)', first)


def has_address(server, tcp=False):
    out = run('/usr/bin/dig', '@' + server, 'example.org.', 'A', '+short', '+time=3',
              '+tries=1', '+tcp' if tcp else '+notcp')
    return any(is_ipv4(line) for line in out.encode().splitlines())


def stop(proc):
    if proc is None or proc.poll() is not None:
        return
    proc.terminate()
    try:
        proc.wait(timeout=4)
    except subprocess.TimeoutExpired:
        proc.kill()
        proc.wait(timeout=2)


def interrupt(*_):
    raise KeyboardInterrupt


def monitor(engine, helper, phone, initial_phone, deadline, health_check=None):
    while True:
        remaining = 3 if deadline is None else min(3, deadline - time.monotonic())
        if remaining <= 0:
            return
        time.sleep(remaining)
        if deadline is not None and time.monotonic() >= deadline:
            return
        if (engine.poll() is not None or (helper and helper.poll() is not None)
                or route(phone).get('interface') != initial_phone or not has_address(DNS)):
            raise RuntimeError('Se perdió el enlace o el DNS del túnel')
        if health_check is not None and not health_check():
            raise RuntimeError('Terminó la conexión al hotspot o falló HTTPS')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--engine', required=True, type=Path)
    parser.add_argument('--config', required=True, type=Path)
    parser.add_argument('--endpoint', required=True, help='Dirección exacta ya verificada por el relay')
    parser.add_argument('--full', action='store_true', help='Capturar rutas generales y publicar DNS temporal')
    parser.add_argument('--helper', type=Path)
    parser.add_argument('--seconds', type=int, default=45, help='Duración máxima. Cero para uso continuo vigilado')
    args = parser.parse_args()
    if os.geteuid() != 0 or args.seconds < 0 or (args.full and args.helper is None):
        parser.error('Requiere administrador, duración válida y --helper para --full')
    run_session(args, json.loads(args.config.read_bytes()))


def run_session(args, settings, health_check=None):
    phone = endpoint(args.endpoint)
    initial_phone = route(phone).get('interface')
    initial_route = route('1.1.1.1')
    initial_tun_route = route(DNS)
    initial_dns = native_dns()
    if not initial_phone or not initial_route or not initial_dns:
        raise RuntimeError('Falta la ruta física al teléfono, la ruta de salida o el DNS principal')
    tun, = settings['inbounds']
    if tun.get('type') != 'tun' or tun['address'][0] != '172.30.255.1/30':
        raise ValueError('Dirección TUN incompatible con el helper')
    for cidr in tun['address']:
        network = ipaddress.ip_network(cidr, strict=False)
        if network.num_addresses > 4:
            raise ValueError('Rango de prueba mayor que el preparado para este proyecto')
        for host in network.hosts():
            old = route(str(host))
            if old and old.get('destination') not in ('default', '0.0.0.0', '::'):
                raise RuntimeError('El rango TUN ya tiene una ruta específica en el Mac')
    if not asyncio.run(test_dns(args.engine, json.loads(json.dumps(settings)))):
        raise RuntimeError('El DNS por el relay falló antes de cambiar rutas')
    tun['route_exclude_address'] = [str(ipaddress.ip_network(phone))]
    tun['dns_mode'] = 'disabled'  # The guarded session helper owns native DNS.
    settings['dns']['disable_cache'] = True  # Health checks must reach the phone.
    if not args.full:
        tun['address'] = [tun['address'][0]]
        tun['route_address'] = [DNS + '/32']
        tun.pop('route_exclude_address', None)
    encoded = json.dumps(settings).encode()
    subprocess.run([args.engine, 'check', '-c', 'stdin'], input=encoded, check=True, timeout=8)
    if health_check is None:
        signal.signal(signal.SIGTERM, interrupt)
        signal.signal(signal.SIGHUP, interrupt)
    signal.signal(signal.SIGALRM, interrupt)
    signal.signal(signal.SIGINT, interrupt)
    signal.pthread_sigmask(signal.SIG_UNBLOCK, {signal.SIGTERM, signal.SIGHUP, signal.SIGALRM, signal.SIGINT})
    engine = helper = None
    interface = None
    active = False
    try:
        deadline = time.monotonic() + args.seconds if args.seconds else None
        signal.alarm(args.seconds)
        engine = subprocess.Popen([args.engine, 'run', '-c', 'stdin'], stdin=subprocess.PIPE,
                                  stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        engine.stdin.write(encoded)
        engine.stdin.close()
        time.sleep(1)
        interface = route(DNS).get('interface', '')
        if engine.poll() is not None or not interface.startswith('utun') or interface == initial_phone:
            raise RuntimeError('No se encontró el TUN esperado')
        if route(phone).get('interface') != initial_phone:
            raise RuntimeError('Cambió la ruta al iPhone')
        data_route = route('1.1.1.1').get('interface')
        if data_route != (interface if args.full else initial_route.get('interface')):
            raise RuntimeError('Ruta de datos inesperada')
        if not has_address(DNS) or not has_address(DNS, tcp=True):
            raise RuntimeError('Falló el DNS UDP/TCP dentro del TUN')
        if args.full:
            helper = subprocess.Popen([args.helper, str(engine.pid)])
            for _ in range(20):
                if helper.poll() is not None or native_dns() == [DNS]:
                    break
                time.sleep(0.25)
            if helper.poll() is not None or native_dns() != [DNS]:
                raise RuntimeError('macOS no confirmó el resolver temporal como principal')
            status = run('/usr/bin/curl', '-q', '--noproxy', '*', '--max-time', '6',
                         '-s', '-o', '/dev/null', '-w', '%{http_code}', 'https://example.org/')
            if status != '200':
                raise RuntimeError('Falló HTTPS con resolución nativa')
        elif native_dns() != initial_dns:
            raise RuntimeError('Cambió inesperadamente el DNS principal')
        active = True
        print('Prueba activa. Ctrl+C restaura DNS y rutas.', flush=True)
        monitor(engine, helper, phone, initial_phone, deadline,
                (lambda: health_check(interface)) if health_check is not None else None)
    except KeyboardInterrupt:
        if not active:
            raise RuntimeError('La prueba terminó antes de verificar la sesión')
        print('Cerrando la sesión.', flush=True)
    finally:
        signal.alarm(0)
        try:
            try:
                stop(helper)
            finally:
                stop(engine)
        finally:
            for _ in range(15):
                if (health_check is not None and interface and DNS not in native_dns()
                        and all(route(host).get('interface') != interface for host in ('1.1.1.1', DNS))):
                    # On hotspot departure DHCP may already be selecting a different uplink.
                    print('Retirados el TUN y su DNS temporal.', flush=True)
                    break
                if (route('1.1.1.1') == initial_route and native_dns() == initial_dns
                        and route(DNS).get('interface') == initial_tun_route.get('interface')):
                    break
                time.sleep(0.2)
            else:
                raise RuntimeError('Comprueba la ruta de salida y scutil --dns antes de repetir')
            if health_check is None:
                print('Restaurados la ruta de salida y los servidores DNS principales.', flush=True)


if __name__ == '__main__':
    main()
