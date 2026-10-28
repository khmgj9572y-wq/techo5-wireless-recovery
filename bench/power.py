#!/usr/bin/env python3
"""Owner-mapped Show 5 bench power controls. Never writes device firmware."""
import argparse,datetime,fcntl,json,os,pathlib,re,signal,subprocess,time,urllib.parse,urllib.request
import bench_config as settings
CFG=settings.PROFILE;ROOT=settings.STATE
TOOL=CFG['uhubctl_cmd'];PORT=CFG['usb']['port']
RELAY_ID=CFG['outlet']['relay_id']
BASE=CFG['outlet']['url'].rstrip('/')+'/'+urllib.parse.quote(RELAY_ID,safe='/')
HUBS={x['location']:x['vidpid'] for x in CFG['usb']['hubs']}

def utc():return datetime.datetime.now(datetime.timezone.utc).isoformat(timespec='milliseconds')
def require(ok,message):
 if not ok:raise RuntimeError(message)
def relay_state():
 with urllib.request.urlopen(BASE,timeout=5) as r:d=json.loads(r.read(4096))
 require(d.get('id')==RELAY_ID and type(d.get('value')) is bool,'Outlet relay identity/readback changed')
 return d['value']
def relay_set(on):
 action='turn_on' if on else 'turn_off'
 req=urllib.request.Request(BASE+'/'+action,data=b'',method='POST')
 with urllib.request.urlopen(req,timeout=5) as r:require(r.status==200,'Relay command failed')
 for _ in range(8):
  if relay_state() is on:return
  time.sleep(.5)
 raise RuntimeError('Relay readback did not reach requested state')
def hub_status():
 r=subprocess.run(TOOL,capture_output=True,text=True,timeout=12,check=True)
 blocks={x.split()[0]:x for x in r.stdout.split('Current status for hub ')[1:]}
 require(set(HUBS)<=set(blocks),'USB hub topology changed')
 for loc,vidpid in HUBS.items():require('['+vidpid+' ' in blocks[loc] and 'ppps]' in blocks[loc],'Wrong hub or port-power capability')
 for item in CFG['usb']['protected']:
  require(item['location'] in blocks and re.search(r'Port '+str(item['port'])+r': .*connect \['+re.escape(item['vidpid'])+' ',blocks[item['location']]),'Protected USB mapping changed')
 return {loc:blocks[loc] for loc in HUBS}

def port_power(block):return bool(re.search(r'Port '+str(PORT)+r': [0-9a-f]+ power(?:\s|$)',block))
def usb_set(hub,on):
 require(hub in HUBS,'Unknown hub')
 subprocess.run(TOOL+['-e','-l',hub,'-p',str(PORT),'-a','on' if on else 'off'],check=True,capture_output=True,text=True,timeout=12)
 require(port_power(hub_status()[hub]) is on,'USB port power-flag readback failed')

def restore_usb_power():
 errors={}
 for hub in HUBS:
  try:usb_set(hub,True)
  except Exception as e:errors[hub]=type(e).__name__
 require(all(port_power(x) for x in hub_status().values()),'USB power restoration needs attention')
 return errors

def preflight_controls():
 settings.require_usb_mapping()
 require(CFG['outlet']['confirmed_for_serial']==CFG['serial'],'Owner outlet mapping required')
 before=hub_status();require(all(port_power(x) for x in before.values()),'USB ports must start powered')
 require(relay_state() is True,'Owner-confirmed power outlet must be reachable and ON')
 for block in before.values():
  line=next(x for x in block.splitlines() if re.search(r'Port '+str(PORT)+':',x))
  descriptor=re.search(r'\bconnect \[(.*?)\]',line)
  require(descriptor is None or not descriptor.group(1) or CFG['serial'] in descriptor.group(1),'Different identified device occupies target port')
 return before

def main():
 parser=argparse.ArgumentParser();parser.add_argument('--execute',action='store_true');a=parser.parse_args()
 settings.require_profile(a.execute);settings.require_usb_mapping()
 require(CFG['outlet']['confirmed_for_serial']==CFG['serial'],'Owner outlet mapping required')
 lock=(ROOT/'bench-power.lock').open('a');fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
 before=hub_status();require(all(port_power(x) for x in before.values()),'USB port must start powered')
 require(relay_state() is True,'Outlet must start ON')
 for block in before.values():
  line=next(x for x in block.splitlines() if re.search(r'Port '+str(PORT)+':',x))
  descriptor=re.search(r'\bconnect \[(.*?)\]',line)
  require(descriptor is None or not descriptor.group(1) or CFG['serial'] in descriptor.group(1),'Different identified device occupies target port')
 print('Preflight passed: owner outlet ON; mapped USB ports powered; protected ports unchanged',flush=True)
 if not a.execute:return
 stamp=datetime.datetime.now(datetime.timezone.utc).strftime('%Y%m%dT%H%M%SZ');report=ROOT/('automated-power-reset-'+stamp+'.json')
 d={'schema':1,'start_utc':utc(),'usb_port':PORT,'protected_ports':CFG['usb']['protected'],'owner_outlet_mapping_confirmed':True,'firmware_written':False,'existing_keys_changed':False,'electrical_vbus_off_verified':False,'events':[]}
 def event(name,**more):
  e=dict(event=name,utc=utc(),**more);d['events'].append(e);report.write_text(json.dumps(d,indent=2)+'\n');report.chmod(0o600);print(json.dumps(e),flush=True)
 def interrupted(signum,frame):raise KeyboardInterrupt('Bench controller interrupted')
 signal.signal(signal.SIGTERM,interrupted)
 attempted=False
 try:
  attempted=True
  for hub in reversed(list(HUBS)):usb_set(hub,False)
  relay_set(False);event('OUTLET_AND_USB_FLAGS_OFF',hold_seconds=60)
  time.sleep(60)
  relay_set(True);event('ADAPTER_POWER_RESTORED',usb_still_off=True,wait_seconds=90)
  time.sleep(90)
 finally:
  if attempted:
   restore_errors=[]
   for _ in range(3):
    try:relay_set(True);break
    except Exception as e:restore_errors.append('outlet:'+type(e).__name__);time.sleep(1)
   for hub in HUBS:
    try:usb_set(hub,True)
    except Exception as e:restore_errors.append('usb '+hub+':'+type(e).__name__)
   try:d['final_outlet_on']=relay_state()
   except Exception:d['final_outlet_on']=None
   try:d['final_usb_power_flags_on']=all(port_power(x) for x in hub_status().values())
   except Exception:d['final_usb_power_flags_on']=None
   event('POWER_RESTORATION',outlet_on=d['final_outlet_on'],usb_power_flags_on=d['final_usb_power_flags_on'],errors=restore_errors)
   require(d['final_outlet_on'] is True and d['final_usb_power_flags_on'] is True,'Power restoration needs attention')
 start=time.monotonic();seen=False
 while time.monotonic()-start<60:
  rows=subprocess.run(['adb','devices','-l'],capture_output=True,text=True,timeout=5).stdout.splitlines()
  if any(x.startswith(CFG['serial']+' ') and ' device ' in (' '+x+' ') for x in rows):seen=True;break
  time.sleep(3)
 event('USB_OBSERVATION',show5_adb_seen=seen)
 print('Report: '+str(report),flush=True)
if __name__=='__main__':main()
