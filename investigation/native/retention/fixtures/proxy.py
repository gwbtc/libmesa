import socket,selectors,json,time,os,signal
from pathlib import Path
root=Path(__file__).resolve().parent
sel=selectors.DefaultSelector(); socks=[]
for i,port in enumerate([31911,31912]):
 s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);s.bind(('127.0.0.1',port));sel.register(s,selectors.EVENT_READ,i);socks.append(s)
seen=0
with (root/'packets.jsonl').open('a',buffering=1) as f:
 while True:
  control=json.loads((root/'proxy-control.json').read_text())
  inject=root/'inject.jsonl'
  if inject.exists():
   lines=inject.read_text().splitlines()
   for line in lines[seen:]:
    v=json.loads(line);i=v['index'];data=bytes.fromhex(v['hex']);socks[1-i].sendto(data,('127.0.0.1',[31902,31901][i]));f.write(json.dumps(dict(time_ns=time.time_ns(),direction=['a-to-b','b-to-a'][i],injected=True,dropped=False,hex=data.hex()))+'\n')
   seen=len(lines)
  for key,_ in sel.select(.1):
   i=key.data;data,src=socks[i].recvfrom(65535)
   control=json.loads((root/'proxy-control.json').read_text())
   dropped=bool(control.get(['drop_a','drop_b'][i],False))
   f.write(json.dumps(dict(time_ns=time.time_ns(),direction=['a-to-b','b-to-a'][i],source=src,dropped=dropped,hex=data.hex()))+'\n')
   kill_label='a' if i==0 else 'b'
   if control.get('kill_'+kill_label+'_once',False):
    control.pop('kill_'+kill_label+'_once');tmp=root/'proxy-control.next';tmp.write_text(json.dumps(control));tmp.replace(root/'proxy-control.json')
    pid=int((root/(kill_label+'.pid')).read_text());assert pid>1
    os.killpg(pid,signal.SIGKILL)
    with (root/'lifecycle.jsonl').open('a') as life:life.write(json.dumps(dict(time_ns=time.time_ns(),action='SIGKILL-on-udp',label=kill_label,pid=pid,packet_hex=data.hex(),dropped=dropped))+'\n')
   if not dropped:socks[1-i].sendto(data,('127.0.0.1',[31902,31901][i]))
