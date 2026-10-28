"""Private operator bindings. Importing this module performs no hardware operations."""
import ipaddress,json,os,pathlib,re,shlex
SOURCE=pathlib.Path(__file__).resolve().parent.parent
EXAMPLE=SOURCE/'bench/profile.example.json'
PROFILE_PATH=pathlib.Path(os.environ.get('T5_BENCH_PROFILE',str(EXAMPLE))).expanduser().resolve()
PROFILE=json.loads(PROFILE_PATH.read_text())
STATE=(PROFILE_PATH.parent/PROFILE['state_dir']).resolve()
def require(ok,message):
 if not ok:raise RuntimeError(message)
def validate(p):
 expected={'schema','owner_confirmed','model','serial','mac_suffix','android_kernel','recovery_kernel','recovery_version','enrolled_ip','misc_sha256','recovery_sha256','system_sha256','state_dir','outlet','usb','uhubctl_cmd','wifi_helper'}
 require(set(p)==expected and p['schema']==1,'Unsupported profile schema')
 require(p['model']=='cronos','Only the reviewed cronos physical layout is supported')
 require(re.fullmatch(r'[A-Za-z0-9_-]{8,40}',p['serial']),'A complete physical USB serial is required')
 require(re.fullmatch(r'[0-9a-f]{4}',p['mac_suffix']),'Invalid factory MAC suffix')
 ipaddress.ip_address(p['enrolled_ip'])
 for key in ['misc_sha256','recovery_sha256','system_sha256']:require(re.fullmatch('[0-9a-f]{64}',p[key]),'Expected partition hashes must be complete')
 for key in ['android_kernel','recovery_kernel','recovery_version']:require(re.fullmatch(r'[A-Za-z0-9._+-]+',p[key]),'Invalid version binding')
 require(set(p['outlet'])=={'url','relay_id','confirmed_for_serial'},'Unexpected outlet fields')
 from urllib.parse import urlsplit
 u=urlsplit(p['outlet']['url']);require(u.scheme in ('http','https') and u.hostname and not u.username and not u.password and not u.query and not u.fragment and u.path in ('','/'),'Outlet must be a credential-free HTTP origin')
 require(p['outlet']['relay_id'].startswith('switch/') and '\n' not in p['outlet']['relay_id'],'Invalid relay entity')
 require(set(p['usb'])=={'mapped_for_serial','port','hubs','protected'} and type(p['usb']['port']) is int and 1<=p['usb']['port']<=31,'Invalid USB profile')
 for h in p['usb']['hubs']:
  require(set(h)=={'location','vidpid'} and re.fullmatch(r'[0-9]+-[0-9]+(?:\.[0-9]+)*',h['location']) and re.fullmatch('[0-9a-f]{4}:[0-9a-f]{4}',h['vidpid']),'Invalid explicit hub mapping')
 for item in p['usb']['protected']:
  require(set(item)=={'location','port','vidpid'} and type(item['port']) is int and 1<=item['port']<=31 and re.fullmatch(r'[0-9]+-[0-9]+(?:\.[0-9]+)*',item['location']) and re.fullmatch('[0-9a-f]{4}:[0-9a-f]{4}',item['vidpid']),'Invalid protected USB binding')
  require(not (item['location'] in {h['location'] for h in p['usb']['hubs']} and item['port']==p['usb']['port']),'Target port overlaps a protected port')
 require(isinstance(p['uhubctl_cmd'],list) and len(p['uhubctl_cmd']) in (1,3) and all(isinstance(x,str) and '\n' not in x for x in p['uhubctl_cmd']) and pathlib.Path(p['uhubctl_cmd'][-1]).name=='uhubctl' and (len(p['uhubctl_cmd'])==1 or p['uhubctl_cmd'][:2]==['sudo','-n']),'uhubctl command must not include control flags')
 w=p['wifi_helper'];require(set(w)=={'path','class','sha256'} and re.fullmatch(r'/data/local/tmp/[A-Za-z0-9_.-]+\.jar',w['path']) and re.fullmatch(r'[A-Za-z][A-Za-z0-9_.]*',w['class']) and re.fullmatch('[0-9a-f]{64}',w['sha256']),'Invalid existing Wi-Fi helper binding')
def require_profile(mutation=True):
 require('T5_BENCH_PROFILE' in os.environ,'Set T5_BENCH_PROFILE to an external private profile; inspect LINUX_HANDOFF.md first')
 validate(PROFILE)
 original=pathlib.Path(os.environ['T5_BENCH_PROFILE']).expanduser()
 require(not original.is_symlink() and PROFILE_PATH.is_file(),'Profile must be a regular file')
 st=PROFILE_PATH.stat();require(st.st_mode&0o777==0o600 and st.st_uid==os.getuid(),'Profile must be owner-only mode 600')
 require(not PROFILE_PATH.is_relative_to(SOURCE) and not STATE.is_relative_to(SOURCE),'Operator profile/state must stay outside this Git checkout')
 if mutation:require(PROFILE['owner_confirmed'] is True and not PROFILE['serial'].upper().startswith('EXAMPLE'),'Owner-confirmed unit binding is required')
 STATE.mkdir(parents=True,exist_ok=True,mode=0o700);require(not STATE.is_symlink() and STATE.stat().st_mode&0o777==0o700,'State directory must be a real private mode-700 directory')
 return PROFILE

def require_usb_mapping():
 require(PROFILE['usb']['mapped_for_serial']==PROFILE['serial'] and PROFILE['usb']['hubs'],'Re-identify and bind the Linux USB topology before port actions')
def bindings():
 values={'BENCH_SERIAL':PROFILE['serial'],'BENCH_RECOVERY_KERNEL':PROFILE['recovery_kernel'],'BENCH_RECOVERY_VERSION':PROFILE['recovery_version'],'BENCH_MISC_SHA':PROFILE['misc_sha256']}
 return ''.join(k+'='+shlex.quote(v)+'\n' for k,v in values.items()).encode()
