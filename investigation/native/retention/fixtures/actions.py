from pathlib import Path
import sys,json,time
sys.path.insert(0,str(Path('investigation/native').resolve()))
from control import run
ROOT=Path(__file__).resolve().parent
V=Path('../output/experimental-live-20261107/release/unpacked/gw-vere').resolve()
NAMES={'a':'~havnum-witsyl-walhex-hacrup--matpyx-nathus-bicnex-palreb','b':'~hantyl-dochus-dilryl-narmul--tabtyv-tantel-dotmeb-nacnub'}
def execute(label,name,source):
 d=ROOT/'commands';d.mkdir(exist_ok=True)
 stamp=time.time_ns();(d/f'{stamp}-{label}-{name}.hoon').write_text(source)
 result=run(V,ROOT/label,source)
 with (ROOT/'actions.jsonl').open('a') as f: f.write(json.dumps(dict(time_ns=stamp,label=label,name=name,result=result))+'\n')
 print(label,name,result.strip(),flush=True)
 return result

def card(label,name,value):
 return execute(label,name,'=/  m  (strand ,vase)\n;<  ~  bind:m  (send-raw-card '+value+')\n(pure:m !>(%dispatched))')
def poke(label,name,value):
 return execute(label,name,'=/  m  (strand ,vase)\n;<  ~  bind:m  (poke-our %crash-probe %noun !>('+value+'))\n(pure:m !>(%dispatched))')
def snapshot(label,name):
 return execute(label,name,'''=/  m  (strand ,vase)
;<  our=@p  bind:m  get-our
;<  now=@da  bind:m  get-time
(pure:m !>(.^(* %gx (en-beam [[our %crash-probe da+now] /state/noun]))))''')
def counts(label,name):
 return execute(label,name,'''=/  m  (strand ,vase)
;<  our=@p  bind:m  get-our
;<  now=@da  bind:m  get-time
=/  st  .^([count=@ud results=(list noun) seen=(list noun)] %gx (en-beam [[our %crash-probe da+now] /state/noun]))
(pure:m !>([count.st (lent results.st) (lent seen.st)]))''')
def start(label):
 import subprocess
 port=31901 if label=='a' else 31902;http=18301 if label=='a' else 18302
 with (ROOT/(label+'.log')).open('ab') as log:
  p=subprocess.Popen([str(V),'-t','-L','--loom','31',str(ROOT/label),'-p',str(port),'--http-port',str(http),'-b','127.0.0.1','--no-dock'],stdout=log,stderr=subprocess.STDOUT,start_new_session=True)
 (ROOT/(label+'.pid')).write_text(str(p.pid))
 with (ROOT/'lifecycle.jsonl').open('a') as f:f.write(json.dumps(dict(time_ns=time.time_ns(),action='start',label=label,pid=p.pid))+'\n')
 print('restarted',label,p.pid,flush=True)
 return p.pid
def close_state(label,name):
 peer=NAMES['b' if label=='a' else 'a']
 return execute(label,name,'''=/  m  (strand ,vase)
;<  our=@p  bind:m  get-our
;<  now=@da  bind:m  get-time
(pure:m !>([.^(* %ax (en-beam [[our %$ da+now] /corked/'''+peer+'''/for])) .^(* %ax (en-beam [[our %$ da+now] /closing/'''+peer+'''/for]))]))''')
