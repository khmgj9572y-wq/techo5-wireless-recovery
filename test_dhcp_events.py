"""Exercise the real event script against a stateful, isolated ip command."""
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

HERE = Path(__file__).resolve().parent
IP_STUB = '''#!{python}
import json, os, sys
from pathlib import Path
p=Path(os.environ['IP_STATE']); s=json.loads(p.read_text()); a=sys.argv[1:]
with open(os.environ['IP_LOG'],'a') as f: f.write(' '.join(a)+'\\n')
if a[:4]==['-4','-o','addr','show']:
    for address in s['addresses']: print('7: wlan0    inet '+address+' scope global wlan0')
elif a[:3]==['-4','addr','flush']: s['addresses']=[]
elif a[:3]==['-4','addr','replace']:
    if a[3] not in s['addresses']: s['addresses'].append(a[3])
elif a[:3]==['-4','route','flush']: s['gateway']=None
elif a[:3]==['-4','route','replace']: s['gateway']=a[a.index('via')+1]
elif a[:2]==['link','set']: pass
else: raise SystemExit('Unexpected ip command: '+repr(a))
p.write_text(json.dumps(s))
'''
