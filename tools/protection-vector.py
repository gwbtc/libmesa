#!/usr/bin/env python3
"""Independent Python transcript and OpenSSL Ed25519 signature; public test seed."""
import argparse
import json
from pathlib import Path
import struct
import subprocess
import tempfile

parser=argparse.ArgumentParser()
parser.add_argument('--check',action='store_true')
args=parser.parse_args()
root=Path(__file__).resolve().parents[1]
lss=next(c for c in json.loads((root/'vectors/lss/vere.json').read_text())['cases'] if c['length']==17425)
seed=bytes([2])*32
domain=b'gw-btc'
path=b'publ/vector\x00\xff'
publisher=0x123456789abcdef0123456789abcdef0
life,rift,bloq,total=7,3,13,lss['length']
transcript=(b'libmesa/v2/public-lss/1\0'+bytes([len(domain)])+domain+publisher.to_bytes(16,'little')
            +struct.pack('<IIBH',rift,life,bloq,len(path))+path+struct.pack('<Q',total)+bytes.fromhex(lss['root']))
with tempfile.TemporaryDirectory() as directory:
    temp=Path(directory)
    key,context,sig=temp/'key.der',temp/'context',temp/'signature'
    key.write_bytes(bytes.fromhex('302e020100300506032b657004220420')+seed)
    context.write_bytes(transcript)
    subprocess.run(['openssl','pkeyutl','-sign','-rawin','-keyform','DER','-inkey',str(key),'-in',str(context),'-out',str(sig)],check=True)
    public=subprocess.check_output(['openssl','pkey','-inform','DER','-in',str(key),'-pubout','-outform','DER'])[-32:]
    result={'seed':seed.hex(),'public':public.hex(),'publisher':f'{publisher:032x}','domain':domain.decode(),
            'life':life,'rift':rift,'bloq':bloq,'path':path.hex(),'total':total,'root':lss['root'],
            'context':transcript.hex(),'signature':sig.read_bytes().hex()}
destination=root/'vectors/lss/signed-public.json'
if args.check: assert json.loads(destination.read_text())==result,'protection vector mismatch'
else: destination.write_text(json.dumps(result,indent=2)+'\n')
print('Python transcript and OpenSSL signature '+('match' if args.check else 'written'))
