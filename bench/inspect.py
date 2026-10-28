#!/usr/bin/env python3
"""Read-only device inventory. Does not request root or change a relay/USB port."""
import json,subprocess
import bench_config as c

def main():
 p=c.require_profile(False);s=p['serial'];result={}
 r=subprocess.run(['adb','devices','-l'],capture_output=True,text=True,timeout=10);result['configured_target_rows']=[x for x in r.stdout.splitlines() if x.startswith(s+' ')]
 if any(' device ' in ' '+x+' ' for x in result['configured_target_rows']):
  for label,cmd in {'board':'getprop ro.product.device','serial':'getprop ro.serialno','android':'getprop ro.build.version.release','lineage':'getprop ro.lineage.version','kernel':'uname -r','uid':'id -u','recovery':'getprop ro.twrp.version','ip':'ip -4 -o addr show wlan0'}.items():
   q=subprocess.run(['adb','-s',s,'shell',cmd],capture_output=True,text=True,timeout=8);result[label]=q.stdout.strip()
 for label,argv in [('adb_server',['adb','server-status']),('usb_hubs',p['uhubctl_cmd'])]:
  try:
   q=subprocess.run(argv,capture_output=True,text=True,timeout=12);result[label]={'exit':q.returncode,'output':q.stdout+q.stderr}
  except FileNotFoundError:result[label]='tool missing'
 print(json.dumps(result,indent=2))
if __name__=='__main__':main()
