#!/usr/bin/env python3
"""One-use, image-preserving cache observer; source queue refuses installs/wipes."""
import argparse,datetime,hashlib,importlib.util,json,os,pathlib,re,subprocess,time,uuid
import bench_config as settings
CFG=settings.PROFILE;HERE=settings.STATE;SOURCE=settings.SOURCE
spec=importlib.util.spec_from_file_location('bcb',SOURCE/'bench/bcb.py');b=importlib.util.module_from_spec(spec);spec.loader.exec_module(b)
S=CFG['serial'];ORIGINAL=CFG['misc_sha256'];RECOVERY=CFG['recovery_sha256']
def now():return datetime.datetime.now(datetime.timezone.utc).isoformat(timespec='milliseconds')
def require(ok,message):
 if not ok:raise RuntimeError(message)
def shell(cmd):return b.read(S,cmd)
def payload(path,data):
 r=b.adb(S,'shell','-T','umask 077; cat > '+path,data=data,timeout=15);require(r.returncode==0,'Staging failed')
 require(shell('sha256sum '+path).split()[0]==hashlib.sha256(data).hexdigest(),'Payload readback failed')
def main():
 parser=argparse.ArgumentParser();parser.add_argument('--execute',action='store_true');parser.add_argument('--softconnect',action='store_true');parser.add_argument('--cmode',action='store_true');parser.add_argument('--adbconfig',action='store_true');parser.add_argument('--wifi-fence',action='store_true');parser.add_argument('--usb-window',action='store_true');parser.add_argument('--expected-backend',choices=['NATIVE','LIBUSB']);parser.add_argument('--allow-rejected-usb-experiment',action='store_true');a=parser.parse_args()
 require(not any([a.softconnect,a.cmode,a.adbconfig]) or a.allow_rejected_usb_experiment,'Read LINUX_HANDOFF.md before repeating a rejected USB experiment')
 settings.require_profile(a.execute)
 if a.execute:
  settings.require_usb_mapping()
  require(CFG["outlet"]["confirmed_for_serial"]==S,"Owner-confirmed power fallback required")
  power_spec=importlib.util.spec_from_file_location('bench_power_preflight',SOURCE/'bench/power.py');power_check=importlib.util.module_from_spec(power_spec);power_spec.loader.exec_module(power_check);power_check.preflight_controls()
 require(sum([a.softconnect,a.cmode,a.adbconfig])<=1,'Select only one USB trial')
 status=subprocess.check_output(['adb','server-status'],text=True);backend=re.search(r'^usb_backend: (\w+)',status,re.M).group(1)
 if a.expected_backend:require(backend==a.expected_backend,'Unexpected ADB server backend')
 require(shell('id -u')=='0' and shell('getprop ro.product.device')==CFG['model'] and shell('getprop ro.serialno')==S and shell('getprop ro.twrp.version')=='','Wrong Android root/identity')
 require(shell('uname -r')==CFG['android_kernel'],'Android kernel differs from reviewed binding')
 require(shell('getprop sys.boot_completed')=='1' and CFG['enrolled_ip']+'/' in shell('ip -4 -o addr show wlan0'),'Test must start with healthy enrolled Android Wi-Fi')
 rows=subprocess.check_output(['adb','devices','-l'],text=True);require(any(x.startswith(S+' ') and 'usb:' in x for x in rows.splitlines()),'USB required')
 require(shell('cat /sys/class/block/mmcblk0p8/start')=='63488' and shell('cat /sys/class/block/mmcblk0p8/size')=='1024','Wrong MISC physical range')
 require(shell('cat /sys/class/block/mmcblk0p11/start')=='130048' and shell('cat /sys/class/block/mmcblk0p11/size')=='65536','Wrong recovery physical range')
 require(shell('sha256sum /dev/block/mmcblk0p11').split()[0]==RECOVERY,'Recovery image changed')
 before=b.snapshot(S);require(hashlib.sha256(before).hexdigest()==ORIGINAL,'MISC differs from rollback baseline')
 require(shell('if [ -e /cache/recovery/openrecoveryscript ] || [ -e /cache/recovery/command ]; then echo queued; else echo clear; fi')=='clear','Another recovery job is queued')
 require(shell("stat -c '%i:%a:%u:%g:%Y' /system"),'System metadata unavailable')
 checkpoint=json.loads((HERE/'current-system-backup.json').read_text());require(checkpoint.get('verified_by')=='bench/verify_backups.py','Run Linux rollback verification first');require(checkpoint['independent_device_hash_verified'] and checkpoint['gzip_crc_and_full_readback_verified'],'System backup not verified')
 with (HERE/checkpoint['file']).open('rb') as f:require(hashlib.file_digest(f,'sha256').hexdigest()==checkpoint['compressed_sha256'],'Backup changed')
 print('Observer preflight passed; recovery/MISC/backups verified; no other recovery command queued',flush=True)
 if not a.execute:return
 token=uuid.uuid4().hex;job='/cache/recovery/t5-observe-'+token;local=HERE/('recovery-observer-'+token);local.mkdir(mode=0o700)
 system_meta=shell("stat -c '%i:%a:%u:%g:%Y' /system")
 scripts={'run.sh':(SOURCE/'bench/templates'/('recovery-observe-softconnect.sh' if a.softconnect else ('recovery-observe-cmode.sh' if a.cmode else ('recovery-observe-adbconfig.sh' if a.adbconfig else 'recovery-observe-return.sh')))).read_bytes(),'network-shutdown.sh':((SOURCE/'bench/experiments/network-shutdown-fence.sh') if a.wifi_fence else (SOURCE/'network-shutdown.sh')).read_bytes(),'binding':settings.bindings()}
 queue=('cmd /sbin/sh '+job+'/run.sh\nT5_DIAGNOSTIC_STOP\n').encode()
 # The invalid sentinel prevents ORS's implicit stock-recovery replacement/reboot if our command refuses.
 require(queue.count(b'\n')==2 and queue.startswith(b'cmd /sbin/sh /cache/recovery/t5-observe-') and queue.endswith(b'T5_DIAGNOSTIC_STOP\n'),'Unsafe observer queue')
 shell('mkdir -m 700 '+job)
 staged=False;armed=False
 content=b.command_bytes(b'boot-recovery')
 report={'schema':1,'token':token,'job':job,'start_utc':now(),'system_metadata_before':system_meta,'firmware_written':False,'existing_keys_changed':False,'host_adb_backend':backend,'usb_softconnect_trial':a.softconnect,'usb_cmode_trial':a.cmode,'usb_adbconfig_trial':a.adbconfig,'wifi_disconnect_fence_trial':a.wifi_fence,'host_usb_window_trial':a.usb_window,'scripts':{k:hashlib.sha256(v).hexdigest() for k,v in scripts.items()}}
 try:
  for name,data in scripts.items():payload(job+'/'+name,data)
  sums=''.join(hashlib.sha256(data).hexdigest()+'  '+name+'\n' for name,data in scripts.items()).encode();payload(job+'/SHA256SUMS',sums)
  payload(job+'/queue',queue)
  shell('ln '+job+'/queue /cache/recovery/openrecoveryscript');staged=True
  require(shell('sha256sum /cache/recovery/openrecoveryscript').split()[0]==hashlib.sha256(queue).hexdigest(),'Queue changed')
  b.save(local/'misc-before.img',before)
  b.write_command(S,content,job+'/command.bin')
  require(b.snapshot(S)==content+before[32:],'Unexpected BCB write');armed=True
 except BaseException:
  if staged:
   r=b.adb(S,'shell','sha256sum /cache/recovery/openrecoveryscript')
   if r.returncode==0 and r.stdout.decode().split()[0]==hashlib.sha256(queue).hexdigest():b.adb(S,'shell','rm /cache/recovery/openrecoveryscript')
  current=b.snapshot(S)
  if current[32:]==before[32:] and current[:32]==content and current[:32]!=before[:32]:
   b.write_command(S,before[:32],job+'/restore-command.bin');require(b.snapshot(S)==before,'BCB rollback failed')
  raise
 report['reboot_requested_utc']=now();(local/'report.json').write_text(json.dumps(report,indent=2)+'\n');print('OBSERVER_REBOOT_UTC '+report['reboot_requested_utc'],flush=True)
 b.adb(S,'reboot',timeout=15)
 start=time.monotonic();observations=[];previous=None;returned=False;first_android=None
 if a.usb_window:
  power_spec=importlib.util.spec_from_file_location('bench_power',SOURCE/'bench/power.py');power=importlib.util.module_from_spec(power_spec);power_spec.loader.exec_module(power)
  import fcntl
  lock=(HERE/'bench-power.lock').open('a');fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
  settings.require_usb_mapping()
  status=power.hub_status();require(all(power.port_power(x) for x in status.values()),'USB must start powered')
  try:
   for hub in reversed(list(power.HUBS)):power.usb_set(hub,False)
   report['host_usb_off_utc']=now();print('HOST_USB_WINDOW_OFF '+report['host_usb_off_utc'],flush=True)
   time.sleep(25)
  finally:
   report['usb_restore_errors']=power.restore_usb_power()
   report['host_usb_on_utc']=now();print('HOST_USB_WINDOW_ON '+report['host_usb_on_utc'],flush=True)
   fcntl.flock(lock,fcntl.LOCK_UN);lock.close()
 while time.monotonic()-start<230:
  try:
   version=shell('getprop ro.twrp.version');boot=shell('getprop sys.boot_completed');state='recovery' if version else 'android'
   if state!=previous:observations.append({'state':state,'observed_utc':now()});previous=state
   if state=='android' and boot=='1':
    returned=True;report['android_ip']=shell('ip -4 -o addr show wlan0')
    if first_android is None:first_android=time.monotonic()
    if CFG['enrolled_ip']+'/' in report['android_ip'] or time.monotonic()-first_android>45:break
  except Exception:pass
  time.sleep(2)
 post_status=subprocess.check_output(['adb','server-status'],text=True);report['host_adb_backend_after']=re.search(r'^usb_backend: (\w+)',post_status,re.M).group(1)
 report['host_backend_unchanged']=report['host_adb_backend_after']==backend
 report.update(android_usb_returned=returned,observations=observations,observation_end_utc=now(),seconds=round(time.monotonic()-start,2))
 (local/'report.json').write_text(json.dumps(report,indent=2)+'\n');print(json.dumps(report),flush=True);print('LOCAL_RESULT '+str(local),flush=True)
if __name__=='__main__':main()
