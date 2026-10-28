import os
from pathlib import Path
import subprocess
import tempfile
import unittest

SCRIPT=Path(__file__).with_name('network-shutdown.sh')
class ShutdownSafety(unittest.TestCase):
 def harness(self,root,body):
  env=dict(os.environ,T5_BASE=str(root/'base'),T5_PROC=str(root/'proc'),T5_RUN=str(root/'run'),T5_SHUTDOWN_LIBRARY='1')
  (root/'base/rootfs/run').mkdir(parents=True,exist_ok=True);(root/'proc').mkdir(exist_ok=True);(root/'run').mkdir(exist_ok=True)
  return subprocess.run(['sh','-c','. "$1"\n'+body,'test',str(SCRIPT)],env=env,capture_output=True,text=True)
 def test_owned_pid_rejects_stale_or_wrong_executable(self):
  with tempfile.TemporaryDirectory() as d:
   r=Path(d).resolve();(r/'base/rootfs/run').mkdir(parents=True);(r/'proc/42').mkdir(parents=True)
   (r/'base/rootfs/run/wpa.pid').write_text('42\n');(r/'proc/42/exe').symlink_to('/unrelated/daemon')
   p=self.harness(r,'if owned_pid wpa; then exit 9; fi')
   self.assertEqual(p.returncode,0,p.stderr)
   (r/'proc/42/exe').unlink();(r/'proc/42/exe').symlink_to(r/'base/rootfs/sbin/wpa_supplicant')
   p=self.harness(r,'owned_pid wpa');self.assertEqual(p.returncode,0,p.stderr);self.assertEqual(p.stdout.strip(),'42')
   for pid in ('0','1','bad'):
    (r/'base/rootfs/run/wpa.pid').write_text(pid+'\n')
    p=self.harness(r,'if owned_pid wpa; then exit 9; fi');self.assertEqual(p.returncode,0)
 def test_control_command_requires_ok_not_just_exit_zero(self):
  with tempfile.TemporaryDirectory() as d:
   r=Path(d).resolve()
   for reply,ok in [('OK',True),('FAIL',False),('UNKNOWN COMMAND',False)]:
    p=self.harness(r,'timeout() { shift; "$@"; }; chroot() { printf "%s\\n" "'+reply+'"; }; wpa_command disconnect')
    self.assertEqual(p.returncode==0,ok,p.stderr)
 def test_supervisor_match_does_not_kill_similar_paths(self):
  with tempfile.TemporaryDirectory() as d:
   r=Path(d).resolve();(r/'proc/42').mkdir(parents=True);(r/'proc/43').mkdir()
   (r/'proc/42/cmdline').write_bytes(b'/sbin/sh\0/sbin/t5-wifi-supervisor.sh\0')
   (r/'proc/43/cmdline').write_bytes(b'/sbin/sh\0/tmp/unrelated/t5-wifi-supervisor.sh\0')
   p=self.harness(r,'kill() { echo "$2"; }; pause_supervisor')
   self.assertEqual(p.returncode,0,p.stderr);self.assertEqual(p.stdout.strip(),'42');self.assertTrue((r/'proc/43/cmdline').exists())
 def test_dhcp_ownership_requires_the_wlan0_client(self):
  with tempfile.TemporaryDirectory() as d:
   r=Path(d).resolve();(r/'base/rootfs/run').mkdir(parents=True);(r/'proc/44').mkdir(parents=True)
   (r/'base/rootfs/run/dhcp.pid').write_text('44\n');(r/'proc/44/exe').symlink_to(r/'base/rootfs/bin/busybox')
   (r/'proc/44/cmdline').write_bytes(b'/sbin/udhcpc\0-f\0-i\0wlan0\0-p\0/run/dhcp.pid\0')
   p=self.harness(r,'owned_pid dhcp');self.assertEqual(p.returncode,0,p.stderr)
   (r/'proc/44/cmdline').write_bytes(b'/bin/busybox\0unrelated\0')
   p=self.harness(r,'if owned_pid dhcp; then exit 9; fi');self.assertEqual(p.returncode,0)
 def test_stale_dhcp_is_removed_without_signalling_a_process(self):
  with tempfile.TemporaryDirectory() as d:
   r=Path(d).resolve();(r/'base/rootfs/run').mkdir(parents=True);(r/'base/rootfs/run/dhcp.pid').write_text('45\n')
   p=self.harness(r,'kill() { exit 9; }; stop_dhcp_client');self.assertEqual(p.returncode,0,p.stderr)
   self.assertFalse((r/'base/rootfs/run/dhcp.pid').exists())
if __name__=='__main__':unittest.main()
