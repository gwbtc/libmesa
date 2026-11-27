from http.server import BaseHTTPRequestHandler,HTTPServer
from pathlib import Path
import json,sys
sys.path.insert(0,str(Path('interop').resolve()));from newt import jam
out=Path(__file__).parent
identities=json.loads((out/'identities.json').read_text())
def noun(x):return tuple(map(noun,x)) if isinstance(x,list) else x
class Handler(BaseHTTPRequestHandler):
 def do_GET(self):
  path=self.path
  if '=lamp=' in path: value=0
  elif '=turf=' in path: value=((int.from_bytes(b'invalid','little'),(int.from_bytes(b'native-test','little'),0)),0)
  else:
   name=path.rsplit('/',1)[-1];entry=next((x for x in identities if x['name'].lstrip('~')==name.lstrip('~')),None)
   if entry is None:self.send_error(404);return
   if '=pynt=' in path:value=(0,noun(entry['point']))
   elif '=saxo=' in path:value=(entry['who'],0)
   else:self.send_error(404);return
  data=jam(value);self.send_response(200);self.send_header('Content-Type','application/x-urb-jam');self.send_header('Content-Length',str(len(data)));self.end_headers();self.wfile.write(data)
HTTPServer(('127.0.0.1',18229),Handler).serve_forever()
