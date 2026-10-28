#!/usr/bin/env python3
"""Audit tracked source before publication; never read untracked operator state."""
import ipaddress
from pathlib import Path
import re
import subprocess
import sys

ROOT = Path(__file__).resolve().parent.parent
ALLOWED = {
    '.gitignore', '.gitattributes', 'LICENSE', 'README.md', 'SECURITY.md', 'profile.example.json',
    'build.py', 'persistent_identity.py', 'prepare_runtime.py', 'loader.sh.in',
    'identity-boot.sh', 'dhcp-event-eap.sh', 'supervisor-eap.sh',
    'test_builder.py', 'test_dhcp_events.py', 'test_persistent_identity.py',
    'patches/wifi-association-fallback.patch', 'patches/LICENSE.mediatek-bsd',
    'identity/go.mod', 'identity/main.go', 'identity/main_test.go', 'tools/audit_export.py',
    'identity/native/main.go', 'identity/native/main_test.go',
    'network-shutdown.sh', 'test_network_shutdown.py',
}
ALLOWED.update({
    'bench/device_check.py',
    'LINUX_HANDOFF.md',
    'bench/adb_mode_window.py',
    'bench/bcb.py',
    'bench/bench_config.py',
    'bench/collect.py',
    'bench/experiments/network-shutdown-fence.sh',
    'bench/inspect.py',
    'bench/observer.py',
    'bench/power.py',
    'bench/profile.example.json',
    'bench/templates/recovery-observe-adbconfig.sh',
    'bench/templates/recovery-observe-cmode.sh',
    'bench/templates/recovery-observe-return.sh',
    'bench/templates/recovery-observe-softconnect.sh',
    'bench/test_bench_config.py',
    'bench/test_disconnect_fence.py',
    'bench/test_power_restore.py',
    'bench/verify_backups.py',
    'bench/wifi_reselect.py',
})

DOC_NETS = [ipaddress.ip_network(n) for n in ('192.0.2.0/24', '198.51.100.0/24', '203.0.113.0/24')]
# Construct patterns to avoid matching the scanner's own literal source.
PEM = re.compile('-{5}BEGIN [A-Z0-9 ]+-{5}')
HOST = re.compile('/' + r'(?:Users|home)/[^/\s]+')
IP = re.compile(r'(?<![\w.])(?:\d{1,3}\.){3}\d{1,3}(?![\w.])')
SERIAL = re.compile(r'(?i)\bg[0-9][a-z0-9]{14}\b')
MAC = re.compile(r'(?i)\b(?:[0-9a-f]{2}:){5}[0-9a-f]{2}\b')


def check(name, content):
    failures = []
    if name not in ALLOWED:
        failures.append('file not on source whitelist')
    try:
        text = content.decode('utf-8')
    except UnicodeDecodeError:
        return failures + ['binary content']
    if '\0' in text or PEM.search(text) or HOST.search(text):
        failures.append('binary, PEM material or local home path')
    if SERIAL.search(text):
        failures.append('literal factory serial')
    if MAC.search(text):
        failures.append('literal MAC address')
    for match in IP.finditer(text):
        try:
            address = ipaddress.ip_address(match.group())
        except ValueError:
            if name.startswith('test_'):
                continue  # deliberate malformed-address rejection fixtures
            failures.append('invalid literal IP address')
            continue
        if not address.is_loopback and not any(address in net for net in DOC_NETS):
            failures.append('non-documentation IP address')
    return failures


def main():
    tracked = subprocess.check_output(['git', 'ls-files', '-z'], cwd=ROOT).split(b'\0')
    problems = []
    count = 0
    for raw in filter(None, tracked):
        name = raw.decode()
        # Inspect staged bytes, exactly what a commit would publish.
        content = subprocess.check_output(['git', 'show', ':' + name], cwd=ROOT)
        for reason in check(name, content):
            problems.append(f'{name}: {reason}')
        count += 1
    if not count:
        problems.append('nothing staged/tracked')
    for problem in problems:
        print(problem, file=sys.stderr)
    if problems:
        return 1
    print(f'Publication audit passed: {count} source/documentation files')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
