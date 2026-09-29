#!/usr/bin/env python3
"""Types lines into a running OxideBSD guest through the QEMU monitor, each followed by Enter.

    OXIDEBSD_QEMU_MONITOR=45454 OXIDEBSD_QEMU_DISPLAY=none cargo run > run.log 2>&1 &
    scripts/qemu_sendkeys.py 45454 'uname -a' 'sysctl kern.ostype'

With OXIDEBSD_QEMU_DISPLAY=none the console is mirrored to COM1 (-D), so the output lands in the
log. QEMU writes the log at its own offset: to find a command's output, note the log's size
before sending and read from there (tail -c +SIZE), rather than appending a marker.
"""
import socket
import sys
import time

KEYS = {
    ' ': 'spc', '/': 'slash', '-': 'minus', '.': 'dot', ':': 'shift-semicolon', '&': 'shift-7',
    '>': 'shift-dot', '<': 'shift-comma', '|': 'shift-backslash', '=': 'equal', '_': 'shift-minus',
    '"': 'shift-apostrophe', "'": 'apostrophe', ';': 'semicolon', ',': 'comma', '$': 'shift-4',
    '?': 'shift-slash', '*': 'shift-8', '~': 'shift-grave_accent', '#': 'shift-3', '!': 'shift-1',
    '(': 'shift-9', ')': 'shift-0', '[': 'bracket_left', ']': 'bracket_right', '{': 'shift-bracket_left',
    '}': 'shift-bracket_right', '+': 'shift-equal', '\\': 'backslash', '@': 'shift-2', '%': 'shift-5',
    '^': 'shift-6', '`': 'grave_accent',
}


def key(c):
    if c.isdigit() or 'a' <= c <= 'z':
        return c
    if 'A' <= c <= 'Z':
        return 'shift-' + c.lower()
    return KEYS[c]


def main():
    if len(sys.argv) < 3:
        sys.exit(__doc__)
    s = socket.create_connection(('127.0.0.1', int(sys.argv[1])))
    time.sleep(0.3)
    s.recv(65536)  # the monitor's banner
    for line in sys.argv[2:]:
        for c in line:
            s.sendall(f'sendkey {key(c)}\n'.encode())
            time.sleep(0.04)
        s.sendall(b'sendkey ret\n')
        time.sleep(0.3)
    s.close()


if __name__ == '__main__':
    main()
