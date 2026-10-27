import importlib.util
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

from test_dhcp_events import IP_STUB

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location("persistent_identity", HERE / "persistent_identity.py")
identity = importlib.util.module_from_spec(spec)
spec.loader.exec_module(identity)


class PersistentIdentityTests(unittest.TestCase):
    def test_public_profile_references_device_key_only(self):
        config, assets, meta = identity.render(HERE / "profile.example.json")
        self.assertIn(b'scan_ssid=1', config)
        self.assertIn(b'domain_suffix_match="radius.example.org"', config)
        self.assertIn(b'private_key="/run/eap-tls/twrp-example01.key"', config)
        self.assertNotIn(b'psk=', config)
        self.assertNotIn(b'PRIVATE KEY', b''.join(assets.values()))
        self.assertFalse(meta['key_in_image'])
        self.assertFalse(meta['network_adb'])

    def test_rejects_host_key_import_or_wrong_filesystem(self):
        with tempfile.TemporaryDirectory() as d:
            path = Path(d) / 'profile.json'
            data = json.loads((HERE / 'profile.example.json').read_text())
            data['private_key'] = 'host-key.pem'
            path.write_text(json.dumps(data))
            with self.assertRaises(ValueError): identity.render(path)
            del data['private_key']; data['persist_uuid'] = 'wrong-filesystem'
            path.write_text(json.dumps(data))
            with self.assertRaises(ValueError): identity.render(path)

    def test_permanent_profile_is_bound_to_factory_serial(self):
        config,_,meta=identity.render(HERE/'profile.example.json')
        self.assertIn(b'identity="twrp-example01"',config)
        self.assertEqual(meta['identity_cn'],'twrp-example01')
        with tempfile.TemporaryDirectory() as d:
            profile=json.loads((HERE/'profile.example.json').read_text())
            profile['cn']='twrp-another-unit'
            path=Path(d)/'profile.json';path.write_text(json.dumps(profile))
            with self.assertRaises(ValueError): identity.render(path)

    def event(self, dns, kind='bound', router='203.0.113.1'):
        import sys
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); (root/'bin').mkdir(); (root/'run').mkdir(); (root/'etc').mkdir()
            stub=root/'bin/ip'; stub.write_text(IP_STUB.format(python=sys.executable)); stub.chmod(0o700)
            state=root/'state.json'; state.write_text(json.dumps({'addresses':['192.0.2.25/24'],'gateway':'192.0.2.1'}))
            (root/'etc/resolv.conf').write_text('nameserver 203.0.113.1\n')
            (root/'run/lease.valid').write_text('7200\n')
            source=(HERE/'dhcp-event-eap.sh').read_text().replace('PATH=/bin:/sbin:/usr/bin:/usr/sbin','PATH='+str(root/'bin')+':/usr/bin:/bin')
            source=source.replace('/run/',str(root/'run')+'/').replace('/etc/resolv.conf',str(root/'etc/resolv.conf'))
            script=root/'event.sh'; script.write_text(source)
            env=dict(os.environ,interface='wlan0',ip='203.0.113.100',mask='24',router=router,dns=dns,serverid='203.0.113.1',lease='7200',IP_STATE=str(state),IP_LOG=str(root/'ip.log'))
            result=subprocess.run(['/bin/sh',str(script),kind],env=env,capture_output=True,text=True)
            return result.returncode,(root/'etc/resolv.conf').read_text(),(root/'run/lease.valid').exists(),json.loads(state.read_text())

    def test_dns_options_applied_and_address_replaced(self):
        status,resolver,valid,state=self.event('198.51.100.53 203.0.113.53')
        self.assertEqual(status,0)
        self.assertEqual(resolver,'nameserver 198.51.100.53\nnameserver 203.0.113.53\n')
        self.assertTrue(valid); self.assertEqual(state['addresses'],['203.0.113.100/24'])

    def test_deconfig_clears_old_dns_and_lease(self):
        status,resolver,valid,state=self.event('198.51.100.53','deconfig')
        self.assertEqual(status,0); self.assertEqual(resolver,''); self.assertFalse(valid)
        self.assertEqual(state['addresses'],[]); self.assertIsNone(state['gateway'])

    def test_bad_dns_never_becomes_valid_lease(self):
        for dns in ('', '198.51.100.999', '198.51.100.53;echo', 'nameserver evil', '0198.51.100.53'):
            status,_,valid,_=self.event(dns)
            self.assertNotEqual(status,0); self.assertFalse(valid)

    def test_missing_identity_does_not_start_wifi(self):
        # Exercise the real supervisor ordering with hardware boundaries mocked.
        source=(HERE/'supervisor-eap.sh').read_text().rsplit('\nmain "$@"',1)[0].replace('. "$BASE/network-policy" || exit 1', ':')
        with tempfile.TemporaryDirectory() as d:
            root=Path(d); (root/'base').mkdir(); (root/'root').mkdir()
            (root/'base/eap-serial').write_text('EXAMPLE01\n')
            (root/'base/eap-kernel').write_text('4.9.77-example\n')
            fixture='''
getprop() { case "$1" in ro.product.device) echo cronos;; ro.serialno) echo EXAMPLE01;; ro.adb.secure) echo 1;; esac; }
uname() { echo 4.9.77-example; }
sha256sum() { return 0; }; grep() { return 0; }; mount() { return 0; }
tcp_off() { return 0; }; firewall() { return 0; }
'''
            # Substitute only the identity boundary; execution must return before firmware loading.
            source=source.replace('/sbin/t5-identity-boot.sh || return 1','identity_check || return 1')
            fixture += '\nidentity_check() { echo identity-attempted; return 1; }\n'
            script=root/'check.sh'; script.write_text(source+f'\nBASE={root}/base\nROOT={root}/root\n'+fixture+'\nprepare\n')
            result=subprocess.run(['/bin/sh',str(script)],capture_output=True,text=True)
            self.assertNotEqual(result.returncode,0)
            self.assertIn('identity-attempted',result.stdout)

    def test_network_listener_detection_fails_closed(self):
        source=(HERE/'supervisor-eap.sh').read_text().rsplit('\nmain "$@"',1)[0].replace('. "$BASE/network-policy" || exit 1', ':')
        with tempfile.TemporaryDirectory() as d:
            root=Path(d); ipv4=root/'tcp'; ipv6=root/'tcp6'
            ipv6.write_text('')
            source=source.replace('/proc/net/tcp /proc/net/tcp6',str(ipv4)+' '+str(ipv6))
            script=root/'listeners.sh'; script.write_text(source+'\nno_external_tcp_listener\n')
            for address,status in [('0100007F:13AD',0),('00000000:15B3',1),('640200C0:15B3',1)]:
                ipv4.write_text('0: '+address+' 00000000:0000 0A 0\n')
                result=subprocess.run(['/bin/sh',str(script)],capture_output=True)
                self.assertEqual(result.returncode,status)
            ipv4.unlink()
            self.assertNotEqual(subprocess.run(['/bin/sh',str(script)],capture_output=True).returncode,0)


if __name__=='__main__': unittest.main()
