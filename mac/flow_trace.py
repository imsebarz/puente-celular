"""Short, opt-in relay measurements. Store durations and port classes only."""
import asyncio
import ipaddress
import json
import os
from pathlib import Path
import tempfile
import time


class FlowTrace:
    def __init__(self, pairing_path):
        self.start = time.monotonic()
        self.live = {}
        self.next_id = 0
        self.file = None
        directory = Path(pairing_path).parent / 'flow-diagnostics'
        try:
            marker = (directory / 'enabled').stat()
        except FileNotFoundError:
            return
        if os.getuid() == 0 or marker.st_uid != os.getuid() or not 0 <= time.time() - marker.st_mtime < 600:
            return
        self.file = tempfile.NamedTemporaryFile(mode='w', dir=directory, prefix='flows-', suffix='.jsonl', delete=False)
        self.tick()

    def emit(self, event, payload):
        if self.file is None:
            return
        elapsed = time.monotonic() - self.start
        if elapsed > 180 or self.file.tell() > 4_000_000:
            self.file.close()
            self.file = None
            return
        try:
            print(json.dumps([round(elapsed, 2), event, payload]), file=self.file, flush=True)
        except OSError:
            self.file = None

    def tick(self):
        now = time.monotonic()
        self.emit('snapshot', [[key, flow['kind'], flow['state'], round(now-flow['start'], 1),
                                round(now-flow['last'], 1), flow['up'], flow['down']]
                               for key, flow in self.live.items()])
        if self.file:
            asyncio.get_running_loop().call_later(2, self.tick)

    def begin(self, proto, host, port):
        if not self.file:
            return None
        try:
            address = ipaddress.ip_address(host)
            family = f'v{address.version}' + ('-priv' if address.is_private else '')
        except ValueError:
            family = 'nombre'
        kind = f'{proto}/{port if port in (53,80,443,853,5223) else "otro"}/{family}'
        self.next_id += 1
        now = time.monotonic()
        self.live[self.next_id] = {'kind':kind,'state':'abriendo','start':now,'last':now,'up':0,'down':0}
        return self.next_id

    def update(self, key, state=None, direction=None, size=0):
        flow = self.live.get(key)
        if flow:
            if state:
                flow['state'] = state
            if direction:
                flow[direction] += size
            flow['last'] = time.monotonic()

    def end(self, key):
        flow = self.live.pop(key, None)
        if flow:
            self.emit('cierre', [key, flow['kind'], flow['state'], round(time.monotonic()-flow['start'], 2),
                                 flow['up'],flow['down']])
