"""Render a public-only profile for a separately enrolled device-held EAP-TLS key."""
import ipaddress
import json
import re
import time
import uuid


def render(profile_path):
    p = json.loads(profile_path.read_text())
    expected = {"model", "serial", "cn", "ssid", "domain_suffix", "ca_sha256", "persist_uuid",
                "kernel_release", "dhcp_server", "dns_servers", "ntp_server"}
    if set(p) != expected:
        raise ValueError("unexpected profile fields; private-key inputs are prohibited")
    if p['model'] != 'cronos':
        raise ValueError("only the separately verified cronos physical layout is supported")
    if not isinstance(p['serial'], str) or not re.fullmatch(r'[A-Za-z0-9]{1,48}', p['serial']):
        raise ValueError("invalid serial")
    if p['cn'] != 'twrp-' + p['serial'].lower():
        raise ValueError("CN must match the selected factory serial")
    if not isinstance(p['kernel_release'], str) or not re.fullmatch(r'[A-Za-z0-9._+\-]{1,128}', p['kernel_release']):
        raise ValueError("invalid kernel release")
    for name in ('ssid', 'domain_suffix'):
        if not isinstance(p[name], str) or not re.fullmatch(r'[A-Za-z0-9.\-]{1,64}', p[name]):
            raise ValueError("invalid network field")
    if len(p['ssid'].encode()) > 32:
        raise ValueError("SSID exceeds 32 bytes")
    if not isinstance(p['ca_sha256'], str) or not re.fullmatch(r'[0-9a-f]{64}', p['ca_sha256']):
        raise ValueError("invalid CA fingerprint")
    try:
        if str(uuid.UUID(p['persist_uuid'])) != p['persist_uuid']:
            raise ValueError("noncanonical persist UUID")
    except (ValueError, TypeError, AttributeError):
        raise ValueError("invalid persist UUID") from None
    if not isinstance(p['dns_servers'], list) or not 1 <= len(p['dns_servers']) <= 3:
        raise ValueError("one to three DNS addresses required")
    for address in [p['dhcp_server'], p['ntp_server'], *p['dns_servers']]:
        if not isinstance(address, str) or str(ipaddress.IPv4Address(address)) != address:
            raise ValueError("canonical IPv4 address required")
    cn = p['cn']
    config = f'''ctrl_interface=/run/wpa
update_config=0
network={{
  ssid="{p['ssid']}"
  scan_ssid=1
  proto=RSN
  key_mgmt=WPA-EAP
  eap=TLS
  identity="{cn}"
  ca_cert="/run/eap-tls/speaker-ca.pem"
  domain_suffix_match="{p['domain_suffix']}"
  client_cert="/run/eap-tls/{cn}.pem"
  private_key="/run/eap-tls/{cn}.key"
  pairwise=CCMP
  group=CCMP
}}
'''.encode()
    assets = {
        'eap-cn': (cn + '\n').encode(),
        'eap-serial': (p['serial'] + '\n').encode(),
        'eap-kernel': (p['kernel_release'] + '\n').encode(),
        'eap-ca-sha256': (p['ca_sha256'] + '\n').encode(),
        'eap-build-floor': (str(int(time.time())) + '\n').encode(),
        'eap-persist-uuid': (p['persist_uuid'] + '\n').encode(),
        'network-policy': (f"DHCP_SERVER='{p['dhcp_server']}'\n"
                           f"DNS_SERVERS='{' '.join(p['dns_servers'])}'\n"
                           f"NTP_SERVER='{p['ntp_server']}'\n").encode(),
        'rootfs/etc/identity-mode': b'device-eap-tls\n',
    }
    return config, assets, {'method': 'EAP-TLS', 'device_held_key': True, 'key_in_image': False,
                            'network_adb': False, 'identity_partition': 'mmcblk0p14', 'identity_cn': cn}
