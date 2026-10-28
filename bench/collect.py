#!/usr/bin/env python3
"""Collect owned one-use observer evidence and optionally remove that exact cache job."""
import argparse,datetime,hashlib,json,pathlib,re,subprocess
import bench_config as settings
CFG=settings.PROFILE;ROOT=settings.STATE;SERIAL=CFG['serial']
def require(x,m):
 if not x:raise RuntimeError(m)
def run(cmd,timeout=20):return subprocess.run(['adb','-s',SERIAL,'shell',cmd],capture_output=True,check=True,timeout=timeout).stdout

def main():
 p=argparse.ArgumentParser();p.add_argument('--token',required=True);p.add_argument('--cleanup',action='store_true');p.add_argument('--full-system-check',action='store_true');a=p.parse_args();settings.require_profile(a.cleanup)
 require(re.fullmatch('[0-9a-f]{32}',a.token),'Invalid job token');case=ROOT/('recovery-observer-'+a.token);report=case/'report.json';d=json.loads(report.read_text());job='/cache/recovery/t5-observe-'+a.token;require(d['job']==job,'Job path differs')
 require(run('id -u').strip()==b'0' and run('getprop ro.product.device').strip().decode()==CFG['model'] and run('getprop ro.serialno').strip().decode()==SERIAL,'Wrong root device')
 raw=run('cat '+job+'/trace.log');f=case/'trace.log';f.write_bytes(raw);f.chmod(0o600)
 for label,cmd in [('android-logcat','logcat -d -b all -v epoch'),('android-wifi','dumpsys wifi'),('kernel','dmesg')]:
  r=run(cmd,30);f=case/(label+'.txt');f.write_bytes(r);f.chmod(0o600)
 for key,part,expected in [('misc',8,CFG['misc_sha256']),('recovery',11,CFG['recovery_sha256'])]:
  value=run('sha256sum /dev/block/mmcblk0p'+str(part)).decode().split()[0];d[key+'_sha256_after']=value;require(value==expected,key+' partition changed')
 d['system_metadata_after']=run("stat -c '%i:%a:%u:%g:%Y' /system").decode().strip();d['system_metadata_unchanged']=d['system_metadata_after']==d['system_metadata_before'];require(d['system_metadata_unchanged'],'System metadata changed')
 if a.full_system_check:
  value=run('sha256sum /dev/block/mmcblk0p12',180).decode().split()[0];before=json.loads((ROOT/'system-before-recovery-observer.json').read_text())['system_partition_sha256'];d['system_partition_sha256_after']=value;d['system_partition_bytes_unchanged']=value==before;require(value==before,'System partition changed')
 d['android_ip_after']=run('ip -4 -o addr show wlan0').decode().strip();d['collected_utc']=datetime.datetime.now(datetime.timezone.utc).isoformat();d['recovery_usb_observed']=any(x['state']=='recovery' for x in d['observations']);d['trace_sha256']=hashlib.sha256(raw).hexdigest()
 if a.cleanup:
  allowed={'run.sh','network-shutdown.sh','SHA256SUMS','queue','command.bin','trace.log','claimed','binding'};require(set(run('ls -A '+job).decode().splitlines())==allowed,'Cache job has unexpected contents')
  for name,sha in d['scripts'].items():require(run('sha256sum '+job+'/'+name).decode().split()[0]==sha,'Payload ownership differs')
  require(run('if [ -e /cache/recovery/openrecoveryscript ]; then echo present; else echo absent; fi').strip()==b'absent','A recovery queue is present; preserving all files')
  run('rm '+' '.join(job+'/'+n for n in sorted(allowed-{'claimed'}))+'; rmdir '+job+'/claimed; rmdir '+job);d['temporary_cache_files_cleaned_up']=True
 report.write_text(json.dumps(d,indent=2)+'\n')
 print('\n'.join(x for x in raw.decode(errors='replace').splitlines() if x.startswith(('MARK','CMODE'))))
 print(json.dumps({k:d.get(k) for k in ['recovery_usb_observed','android_ip_after','system_metadata_unchanged','system_partition_bytes_unchanged','temporary_cache_files_cleaned_up']}))
if __name__=='__main__':main()
