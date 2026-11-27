import socket,selectors,json,time
from pathlib import Path
p=Path(__file__).parent
s=selectors.DefaultSelector();ports=[31850,31851];dest=[31738,31727];ss=[]
for i,port in enumerate(ports):
 x=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);x.bind(('127.0.0.1',port));s.register(x,selectors.EVENT_READ,i);ss.append(x)
seen=0
with (p/'packets.jsonl').open('a',buffering=1) as f:
 while True:
  control=p/'inject.jsonl'
  if control.exists():
   lines=control.read_text().splitlines()
   for text in lines[seen:]:
    inj=json.loads(text);i=inj['index'];data=bytes.fromhex(inj['hex']);f.write(json.dumps({'time_ns':time.time_ns(),'direction':['a-to-b','b-to-a'][i],'injected_replay':True,'destination_port':dest[i],'hex':data.hex()})+'\n');ss[1-i].sendto(data,('127.0.0.1',dest[i]))
   seen=len(lines)
  for key,_ in s.select(.2):
   i=key.data;data,src=ss[i].recvfrom(65535);row={'time_ns':time.time_ns(),'direction':['a-to-b','b-to-a'][i],'source':src,'destination_port':dest[i],'hex':data.hex()};row['dropped']=bool(i==0 and b'chum/' in data and not (p/'release').exists());f.write(json.dumps(row)+'\n');
   if not row['dropped']:ss[1-i].sendto(data,('127.0.0.1',dest[i]))
