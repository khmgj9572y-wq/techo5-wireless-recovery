#!/usr/bin/env python3
"""Select an existing enrolled profile through the exact already-reviewed on-device helper. No enrollment/key creation."""
import argparse,json,shlex,subprocess
import bench_config as c

def main():
 p=argparse.ArgumentParser();p.add_argument('--execute',action='store_true');a=p.parse_args();cfg=c.require_profile(a.execute);s=cfg['serial'];w=cfg['wifi_helper']
 def read(cmd):return subprocess.check_output(['adb','-s',s,'shell',cmd],text=True,timeout=15).strip()
 c.require(read('getprop ro.product.device')==cfg['model'] and read('getprop ro.serialno')==s and read('getprop ro.twrp.version')=='','Wrong Android unit')
 c.require(read('id -u')=='0','Existing rooted debugging required')
 c.require(read('sha256sum '+shlex.quote(w['path'])).split()[0]==w['sha256'] and w['sha256']!='0'*64,'Helper is missing or differs; do not install a substitute automatically')
 action='prefer' if a.execute else 'inspect';cmd='CLASSPATH='+shlex.quote(w['path'])+' app_process /system/bin '+shlex.quote(w['class'])+' '+action
 text=read(cmd);data=json.loads(next(x for x in text.splitlines() if x.startswith('{')))
 (c.STATE/'wifi-reselect-result.json').write_text(json.dumps(data,indent=2)+'\n');(c.STATE/'wifi-reselect-result.json').chmod(0o600);print(json.dumps(data))
if __name__=='__main__':main()
