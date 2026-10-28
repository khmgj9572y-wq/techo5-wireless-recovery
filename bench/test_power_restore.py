import importlib.util,pathlib,unittest
from unittest.mock import patch,call
p=pathlib.Path(__file__).with_name('power.py');s=importlib.util.spec_from_file_location('bench_power_tested',p);m=importlib.util.module_from_spec(s);s.loader.exec_module(m)
class RestoreSafety(unittest.TestCase):
 def setUp(self):
  self.hubs=patch.object(m,'HUBS',{'1-1':'1111:1111','1-2':'2222:2222'});self.hubs.start();self.addCleanup(self.hubs.stop)
 def test_attempts_both_hubs_when_first_command_errors(self):
  with patch.object(m,'usb_set',side_effect=[RuntimeError('fixture'),None]) as usb,patch.object(m,'hub_status',return_value={'1-1':'on','1-2':'on'}),patch.object(m,'port_power',return_value=True):
   errors=m.restore_usb_power();self.assertEqual(usb.call_args_list,[call('1-1',True),call('1-2',True)]);self.assertEqual(errors,{'1-1':'RuntimeError'})
 def test_refuses_to_claim_restoration_without_power_readback(self):
  with patch.object(m,'usb_set') as usb,patch.object(m,'hub_status',return_value={'1-1':'off','1-2':'on'}),patch.object(m,'port_power',side_effect=[False,True]):
   with self.assertRaises(RuntimeError):m.restore_usb_power()
   self.assertEqual(usb.call_count,2)
if __name__=='__main__':unittest.main()
