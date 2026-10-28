import json,os,pathlib,tempfile,unittest
from unittest.mock import patch
import bench_config as c
class ProfileSafety(unittest.TestCase):
 def example(self):return json.loads(c.EXAMPLE.read_text())
 def test_example_format_is_valid_but_not_authorized(self):
  p=self.example();c.validate(p);self.assertFalse(p['owner_confirmed']);self.assertFalse(p['usb']['mapped_for_serial'])
 def test_network_target_is_not_a_physical_serial(self):
  p=self.example();p['serial']='192.0.2.2:5555'
  with self.assertRaises(RuntimeError):c.validate(p)
 def test_readonly_hub_command_cannot_hide_action_flags(self):
  for argv in [['uhubctl','-a','off'],['sudo','uhubctl','-R']]:
   p=self.example();p['uhubctl_cmd']=argv
   with self.assertRaises(RuntimeError):c.validate(p)
 def test_private_permissions_checked_before_state_creation(self):
  with tempfile.TemporaryDirectory() as tmp:
   root=pathlib.Path(tmp);f=root/'operator.json';p=self.example();p['serial']='TESTUNIT01';p['owner_confirmed']=True;f.write_text(json.dumps(p));f.chmod(0o644)
   with patch.dict(os.environ,{'T5_BENCH_PROFILE':str(f)}),patch.object(c,'PROFILE_PATH',f),patch.object(c,'PROFILE',p),patch.object(c,'STATE',root/'state'):
    with self.assertRaises(RuntimeError):c.require_profile()
    self.assertFalse((root/'state').exists());f.chmod(0o600);c.require_profile();self.assertEqual((root/'state').stat().st_mode&0o777,0o700)
 def test_target_and_protected_port_cannot_overlap(self):
  p=self.example();p['usb']['hubs']=[{'location':'1-1','vidpid':'1111:1111'}];p['usb']['protected']=[{'location':'1-1','port':2,'vidpid':'1111:1111'}]
  with self.assertRaises(RuntimeError):c.validate(p)
 def test_boolean_port_is_not_an_integer_port(self):
  p=self.example();p['usb']['port']=True
  with self.assertRaises(RuntimeError):c.validate(p)
 def test_other_hub_can_protect_same_port_number(self):
  p=self.example();p['usb']['hubs']=[{'location':'1-1','vidpid':'1111:1111'}];p['usb']['protected']=[{'location':'2-1','port':2,'vidpid':'2222:2222'}];c.validate(p)
 def test_unverified_usb_mapping_refused(self):
  with patch.object(c,'PROFILE',self.example()):
   with self.assertRaises(RuntimeError):c.require_usb_mapping()
if __name__=='__main__':unittest.main()
