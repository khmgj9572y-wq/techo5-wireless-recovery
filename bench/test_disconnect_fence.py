import os,pathlib,subprocess,tempfile,unittest
SCRIPT=pathlib.Path(__file__).parent/'experiments/network-shutdown-fence.sh'
class FenceSafety(unittest.TestCase):
 def trial(self,mode):
  with tempfile.TemporaryDirectory() as d:
   root=pathlib.Path(d).resolve();base=root/'base/rootfs';(base/'run').mkdir(parents=True);(base/'sbin').mkdir();proc=root/'proc';(proc/'42').mkdir(parents=True);(proc/'42/exe').symlink_to(base/'sbin/wpa_supplicant');(base/'run/wpa.pid').write_text('42\n');net=root/'sys/class/net/wlan0';net.mkdir(parents=True);(net/'carrier').write_text('1\n');(net/'flags').write_text('0x1003\n');(root/'count').write_text('0')
   env=dict(os.environ,T5_BASE=str(root/'base'),T5_PROC=str(proc),T5_RUN=str(root/'run'),T5_SYS=str(root/'sys'),T5_SHUTDOWN_LIBRARY='1',FIXTURE=str(root),CASE=mode)
   body='''
. "$1"
sleep() { :; }
timeout() { shift; "$@"; }
chroot() {
 last=
 for last; do :; done
 echo "$last" >> "$FIXTURE/calls"
 case "$last" in
 status)
  c=$(cat "$FIXTURE/count"); c=$((c+1)); echo "$c" > "$FIXTURE/count"
  if [ "$CASE" = success ] && [ "$c" -ge 2 ]; then echo 0 > "$T5_SYS/class/net/wlan0/carrier"; echo wpa_state=DISCONNECTED;
  elif [ "$CASE" = carrier ]; then echo wpa_state=DISCONNECTED;
  else echo wpa_state=COMPLETED; fi;;
 terminate) rm "$T5_PROC/42/exe"; rmdir "$T5_PROC/42"; echo OK;;
 *) echo OK;; esac
}
disconnect_supplicant
'''
   r=subprocess.run(['sh','-c',body,'test',str(SCRIPT)],env=env,text=True,capture_output=True)
   return r,(root/'calls').read_text().splitlines()
 def test_waits_for_state_and_carrier_before_termination(self):
  r,calls=self.trial('success');self.assertEqual(r.returncode,0,r.stderr);self.assertEqual(calls,['disconnect','status','status','pmksa_flush','terminate'])
 def test_connected_state_refuses_to_terminate(self):
  r,calls=self.trial('connected');self.assertNotEqual(r.returncode,0);self.assertNotIn('terminate',calls);self.assertNotIn('pmksa_flush',calls)
 def test_disconnected_supplicant_with_carrier_refuses_to_terminate(self):
  r,calls=self.trial('carrier');self.assertNotEqual(r.returncode,0);self.assertNotIn('terminate',calls)
if __name__=='__main__':unittest.main()
