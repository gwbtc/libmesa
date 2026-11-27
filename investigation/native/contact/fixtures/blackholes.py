import socket,selectors,json,time
from pathlib import Path
p=Path(__file__).parent
sel=selectors.DefaultSelector()
for port in [31402, 31463]:
 s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);s.bind(('127.0.0.1',port));sel.register(s,selectors.EVENT_READ,port)
with (p/'blackholes.jsonl').open('a',buffering=1) as f:
 while True:
  for key,_ in sel.select():
   data,src=key.fileobj.recvfrom(65535);f.write(json.dumps({'time_ns':time.time_ns(),'port':key.data,'source':src,'bytes':len(data),'hex':data.hex()})+'\n')
