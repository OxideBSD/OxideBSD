#!/usr/bin/env python3
"""Sends a file's QEMU monitor commands, one a line, to the monitor on a Unix socket:

    qemu_monitor_send.py SOCKET FILE

For tests (qemu_common.sh's QEMU_MONITOR_INPUT): `sendkey z` presses a key as a real keyboard
would, through the guest's PS/2 controller. Lines starting with `#` and empty lines are skipped;
`sleep N` waits N seconds (a fraction allowed) instead of sending anything.
"""
import socket
import sys
import time


def main():
    if len(sys.argv) != 3:
        sys.exit(__doc__)
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    s.connect(sys.argv[1])
    s.settimeout(1.0)
    time.sleep(0.2)
    try:
        s.recv(65536)  # the banner
    except socket.timeout:
        pass
    with open(sys.argv[2]) as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith('#'):
                continue
            if line.startswith('sleep '):
                time.sleep(float(line.split()[1]))
                continue
            s.sendall(line.encode() + b'\n')
            # A key press and its release take the guest a moment; keep them in order.
            time.sleep(0.15)
    s.close()


main()
