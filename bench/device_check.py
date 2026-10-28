#!/usr/bin/env python3
"""Read-only physical partition check against verified private rollback artifacts."""
import datetime,json,subprocess
import bench_config as c

def main():
 p=c.require_profile(False);s=p['serial'];receipt=c.STATE/'current-system-backup.json';d=json.loads(receipt.read_text())
 c.require(d.get('verified_by')=='bench/verify_backups.py' and d.get('gzip_crc_and_full_readback_verified'),'Verify local rollback artifacts first')
 def read(cmd,timeout=15):return subprocess.check_output(['adb','-s',s,'shell',cmd],text=True,timeout=timeout).strip()
 c.require(read('getprop ro.product.device')==p['model'] and read('getprop ro.serialno')==s and read('getprop ro.twrp.version')=='' and read('id -u')=='0','Check must start in authorized rooted Android on the bound unit')
 c.require(read('uname -r')==p['android_kernel'],'Android kernel differs from binding')
 geometry={8:('63488','1024'),9:('64512','32768'),11:('130048','65536'),12:('195584','6354944')}
 expected={8:p['misc_sha256'],9:d['artifacts']['boot']['sha256'],11:p['recovery_sha256'],12:p['system_sha256']};measured={}
 for part,(start,size) in geometry.items():
  c.require(read(f'cat /sys/class/block/mmcblk0p{part}/start')==start and read(f'cat /sys/class/block/mmcblk0p{part}/size')==size,'Physical partition geometry differs')
  sha=read(f'sha256sum /dev/block/mmcblk0p{part}',180).split()[0];c.require(sha==expected[part],'Current physical partition differs from verified rollback');measured[str(part)]=sha
 d['independent_device_hash_verified']=True;d['device_checked_serial']=s;d['device_checked_kernel']=p['android_kernel'];d['device_checked_utc']=datetime.datetime.now(datetime.timezone.utc).isoformat();d['device_partition_hashes']=measured
 receipt.write_text(json.dumps(d,indent=2)+'\n');receipt.chmod(0o600)
 print('Bound device p8/p9/p11/p12 match verified rollback artifacts; no device writes occurred')
if __name__=='__main__':main()
