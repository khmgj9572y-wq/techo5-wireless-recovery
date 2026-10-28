#!/usr/bin/env python3
"""Verify private rollback artifacts, including full gzip CRC/raw-system hash, without device I/O."""
import datetime,gzip,hashlib,json,pathlib
import bench_config as c

def digest(path):
 with path.open('rb') as f:return hashlib.file_digest(f,'sha256').hexdigest()
def main():
 p=c.require_profile(False);m=json.loads((c.STATE/'rollback/manifest.json').read_text())
 c.require(m['schema']==1 and m['model']==p['model'] and m['serial']==p['serial'],'Rollback manifest is for another unit')
 c.require(set(m['files'])=={'boot','recovery','system','misc'},'Only non-key rollback partition artifacts are accepted')
 sizes={'boot':16777216,'recovery':33554432,'misc':524288};verified={}
 for name,item in m['files'].items():
  original=c.STATE/item['file'];path=original.resolve();c.require(path.is_relative_to(c.STATE) and not original.is_symlink() and path.is_file(),'Rollback artifact escaped private state')
  st=path.stat();c.require(st.st_mode&0o777==0o600,'Rollback artifact must be mode 600')
  sha=digest(path);c.require(sha==item['sha256'],'Rollback artifact checksum differs')
  if name in sizes:c.require(st.st_size==sizes[name],'Wrong physical rollback artifact size')
  if name in ('boot','recovery'):
   with path.open('rb') as f:c.require(f.read(8)==b'ANDROID!','Wrong boot-image format')
  if name=='recovery':c.require(sha==p['recovery_sha256'],'Recovery artifact differs from reviewed binding')
  if name=='misc':c.require(sha==p['misc_sha256'],'MISC artifact differs from reviewed binding')
  verified[name]={'file':item['file'],'sha256':sha,'size':st.st_size}
 raw_sha=hashlib.sha256();raw_size=0
 with gzip.open(c.STATE/verified['system']['file'],'rb') as f:
  while block:=f.read(4*1024*1024):
   raw_size+=len(block);c.require(raw_size<=3253731328,'Expanded system exceeds physical p12');raw_sha.update(block)
 c.require(raw_size==3253731328 and raw_sha.hexdigest()==p['system_sha256'],'Full raw-system verification failed')
 receipt={'schema':1,'file':verified['system']['file'],'size':raw_size,'raw_sha256':raw_sha.hexdigest(),'compressed_size':verified['system']['size'],'compressed_sha256':verified['system']['sha256'],'independent_device_hash_verified':False,'gzip_crc_and_full_readback_verified':True,'verified_utc':datetime.datetime.now(datetime.timezone.utc).isoformat(),'verified_by':'bench/verify_backups.py','artifacts':verified}
 out=c.STATE/'current-system-backup.json';out.write_text(json.dumps(receipt,indent=2)+'\n');out.chmod(0o600)
 before=c.STATE/'system-before-recovery-observer.json';before.write_text(json.dumps({'system_partition_sha256':p['system_sha256'],'source':'Verified private rollback manifest'},indent=2)+'\n');before.chmod(0o600)
 print('Four private rollback artifacts verified; full system gzip CRC and raw hash passed; no device commands sent')
if __name__=='__main__':main()
