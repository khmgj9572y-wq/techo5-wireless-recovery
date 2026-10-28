#!/usr/bin/env python3
"""Bench-only ADB root/unroot with a bounded host USB reconnect window."""
import argparse,datetime,fcntl,importlib.util,json,pathlib,selectors,subprocess,time
import bench_config as settings
CFG=settings.PROFILE;ROOT=settings.STATE;S=CFG['serial']
spec=importlib.util.spec_from_file_location('power',settings.SOURCE/'bench/power.py');power=importlib.util.module_from_spec(spec);spec.loader.exec_module(power)
def now():return datetime.datetime.now(datetime.timezone.utc).isoformat(timespec='milliseconds')
def read(cmd,timeout=5):return subprocess.check_output(['adb','-s',S,'shell',cmd],stderr=subprocess.DEVNULL,text=True,timeout=timeout).strip()
def main():
 p=argparse.ArgumentParser();p.add_argument('--mode',choices=['root','unroot'],default='root');p.add_argument('--execute',action='store_true');a=p.parse_args();settings.require_profile(a.execute);desired='0' if a.mode=='root' else '2000'
 power.require(read('getprop ro.product.device')=='cronos' and read('getprop ro.serialno')==S and read('getprop ro.twrp.version')=='','Wrong Android unit')
 before=read('id -u');power.require(before in ('0','2000'),'Unexpected UID')
 if before==desired:print('ADB already has desired UID '+desired);return
 if not a.execute:print('Ready for runtime '+a.mode+' test; no action performed');return
 lock=(ROOT/'bench-power.lock').open('a');fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
 settings.require_usb_mapping()
 status=power.hub_status();power.require(all(power.port_power(x) for x in status.values()),'USB not initially powered')
 report={'start_utc':now(),'mode':a.mode,'before_uid':before,'adapter_power_changed':False,'only_usb_port':power.PORT}
 proc=subprocess.Popen(['adb','-s',S,a.mode],stdout=subprocess.PIPE,stderr=subprocess.STDOUT,text=True,bufsize=1)
 select=selectors.DefaultSelector();select.register(proc.stdout,selectors.EVENT_READ);power.require(bool(select.select(5)),'No ADB mode acknowledgment');line=proc.stdout.readline();report['ack']=line.strip();select.close()
 power.require('restarting adbd' in line.lower(),'No daemon restart acknowledgment: '+line)
 try:
  for hub in reversed(list(power.HUBS)):power.usb_set(hub,False)
  report['usb_off_utc']=now();time.sleep(12)
 finally:
  report['usb_restore_errors']=power.restore_usb_power()
  report['usb_on_utc']=now()
 try:tail=proc.communicate(timeout=15)[0]
 except subprocess.TimeoutExpired:proc.terminate();tail=proc.communicate(timeout=5)[0]
 report['client_exit']=proc.returncode;report['client_output_tail']=tail.strip();uid=None
 for _ in range(12):
  try:
   uid=read('id -u',3)
   if uid==desired:break
  except Exception:pass
  time.sleep(2)
 report['after_uid']=uid;report['verified']=uid==desired;report['end_utc']=now();f=ROOT/('adb-'+a.mode+'-window-'+datetime.datetime.now(datetime.timezone.utc).strftime('%Y%m%dT%H%M%SZ')+'.json');f.write_text(json.dumps(report,indent=2)+'\n');f.chmod(0o600);print(json.dumps(report));power.require(report['verified'],'ADB mode did not reconnect')
if __name__=='__main__':main()
