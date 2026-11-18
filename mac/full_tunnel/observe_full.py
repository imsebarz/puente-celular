"""Observe a bounded full-tunnel trial from a separate, unprivileged terminal."""
import argparse
import re
import subprocess
import time
import uuid


def output(*cmd):
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=7)
    except subprocess.TimeoutExpired:
        return ''
    return result.stdout.strip() if result.returncode == 0 else ''


def route(address):
    family = '-inet6' if ':' in address else '-inet'
    raw = output('/sbin/route', '-n', 'get', family, address)
    return dict(re.findall(r'^\s*(interface|gateway|destination):\s*(\S+)', raw, re.M))


def dns():
    raw = output('/usr/sbin/scutil', '--dns').partition('DNS configuration (for scoped queries)')[0]
    first = raw.partition('resolver #1')[2].partition('resolver #2')[0]
    return re.findall(r'nameserver\[\d+\]\s*:\s*(\S+)', first)


def browse():
    return output('/usr/bin/curl', '-q', '-4', '--noproxy', '*', '--max-time', '5',
                  '-s', '-o', '/dev/null', '-w', '%{http_code} %{remote_ip}', 'https://example.org/').split()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--endpoint', required=True)
    endpoint = parser.parse_args().endpoint
    target = '172.30.255.2'
    baseline = [route(host) for host in ('default', '1.1.1.1', target)]
    original_dns = dns()
    phone_interface = route(endpoint).get('interface')
    assert all(baseline) and phone_interface and original_dns and browse()[:1] == ['200']
    print('Referencia registrada. Esperando el TUN.', flush=True)
    started = None
    last_dns = original_dns
    checks = 0
    failed_checks = 0
    fresh = False
    next_check = 0
    wait_until = time.monotonic() + 300
    while time.monotonic() < wait_until:
        tun = route(target).get('interface', '')
        now = time.monotonic()
        if started is None and tun.startswith('utun') and tun != phone_interface:
            started = now
            print('TUN observado:', tun, flush=True)
        if started is not None:
            current_dns = dns()
            elapsed = now - started
            if current_dns != last_dns:
                print(f'{elapsed:.1f} s: resolver principal {current_dns}', flush=True)
                last_dns = current_dns
            if tun == baseline[2]['interface'] and current_dns == original_dns:
                restored = all(route(host) == original for host, original in zip(
                    ('default', '1.1.1.1', target), baseline))
                final_http = browse()[:1] == ['200']
                print(f'{elapsed:.1f} s: rutas originales={restored}, DNS original=True, HTTPS final={final_http}', flush=True)
                print(f'Muestras HTTPS verificadas={checks}, sin verificar={failed_checks}', flush=True)
                return bool(restored and final_http and fresh and checks >= 2 and failed_checks == 0
                            and 40 <= elapsed <= 52)
            if current_dns == [target] and now >= next_check:
                if not fresh:
                    # New public wildcard name exercises the native macOS resolver on every run.
                    name = f'{uuid.uuid4().hex}.1-1-1-1.sslip.io'
                    native = output('/usr/bin/dscacheutil', '-q', 'host', '-a', 'name', name)
                    fresh = bool(re.search(r'^ip_address:\s+1\.1\.1\.1$', native, re.M))
                http = browse()
                status = http[0] if http else 'sin respuesta'
                web_interface = route(http[1]).get('interface') if len(http) == 2 else None
                phone_now = route(endpoint).get('interface')
                dns_matches = dns() == [target]
                correct = (status == '200' and web_interface == tun
                           and phone_now == phone_interface and dns_matches)
                print(f'{elapsed:.1f} s: HTTP={status}, interfaz HTTPS={web_interface}, '
                      f'interfaz iPhone={phone_now}, resolver temporal={dns_matches}, '
                      f'nombre nuevo resuelto={fresh}', flush=True)
                checks += int(correct)
                failed_checks += int(not correct)
                next_check = now + 8
            if elapsed > 56:
                print('El TUN o su DNS siguen activos fuera del plazo.', flush=True)
                return False
        time.sleep(0.25)
    return False


if __name__ == '__main__':
    raise SystemExit(0 if main() else 1)
