#!/usr/bin/env python3
"""Compile the pinned C LSS source with portable BLAKE3; regenerate/check vectors.
No Rust implementation is used. The shim supplies Vere allocation/types only.
"""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import tempfile

parser = argparse.ArgumentParser()
parser.add_argument('--vere', type=Path, required=True)
parser.add_argument('--urcrypt', type=Path, required=True)
parser.add_argument('--check', action='store_true')
args = parser.parse_args()
lss_path = args.vere / 'pkg/vere/io/lss.c'
header_path = args.vere / 'pkg/vere/io/lss.h'
wrapper_path = args.urcrypt / 'urcrypt/blake3.c'
shim = r'''
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include "blake3_impl.h"
#define blake3_compress_in_place blake3_compress_in_place_portable
#define blake3_compress_xof blake3_compress_xof_portable
typedef uint8_t c3_y; typedef uint8_t c3_b; typedef int c3_o;
typedef uint32_t c3_w; typedef uint64_t c3_d; typedef void arena;
#define c3y 0
#define c3n 1
#define __(x) ((x) ? c3y : c3n)
#define c3_calloc(n) calloc(1, (n))
#define c3_malloc malloc
#define c3_free free
#define c3_min(a,b) ((a)<(b)?(a):(b))
#define c3_bits_word(x) ((x) ? 32-__builtin_clz((unsigned)(x)) : 0)
#define c3_tz_w(x) __builtin_ctz((unsigned)(x))
#define new(a,t,n) ((t*)calloc((n),sizeof(t)))
'''
header = '\n'.join(l for l in header_path.read_text().splitlines() if not l.startswith('#include'))
wrapper = wrapper_path.read_text()
wrapper = wrapper[wrapper.index('void\nurcrypt_blake3_chunk_output'):]
lss = lss_path.read_text().split('#ifdef LSS_TEST')[0]
lss = '\n'.join(l for l in lss.splitlines() if not l.startswith('#include'))
driver = r'''
static void hex(const uint8_t* p, size_t n) { putchar('"'); for(size_t i=0;i<n;i++) printf("%02x",p[i]); putchar('"'); }
int main(void) {
  unsigned sizes[] = {1,1024,1025,2048,2049,4096,6145,7169,8192,17425,65537,1048576};
  puts("[");
  for(unsigned k=0;k<sizeof(sizes)/sizeof(*sizes);k++) {
    unsigned len=sizes[k], n=(len+1023)/1024;
    uint8_t* data=malloc(len);
    for(unsigned i=0;i<len;i++) data[i]=(i%29>=24)?0:(uint8_t)(i%251);
    lss_builder b={0}; lss_builder_init(&b,n);
    for(unsigned i=0;i<n;i++) lss_builder_ingest(&b,data+i*1024,c3_min(1024,len-i*1024));
    lss_hash* proof=lss_builder_finalize(&b);
    if(n==1) lss_complete_inline_proof(proof,data,len);
    lss_hash root; lss_root(root,proof,lss_proof_size(n));
    lss_verifier v={0}; lss_verifier_init(&v,0,n,proof,NULL);
    for(unsigned i=0;i<n;i++) if(c3y!=lss_verifier_ingest(&v,data+i*1024,c3_min(1024,len-i*1024),lss_builder_pair(&b,i))) return 2;
    if(k) puts(",");
    printf("{\"length\":%u,\"root\":",len); hex(root,32);
    printf(",\"proof\":"); hex((uint8_t*)proof,lss_proof_size(n)*32);
    printf(",\"pairs\":[");
    for(unsigned i=0;i<n;i++){ if(i) putchar(','); lss_pair* p=lss_builder_pair(&b,i); if(p) hex((uint8_t*)p,64); else printf("null"); }
    printf("]}"); free(data); free(b.proof); free(b.pairs); free(v.pairs);
  }
  puts("]"); return 0;
}
'''
with tempfile.TemporaryDirectory() as temp:
    source, binary = Path(temp) / 'reference.c', Path(temp) / 'reference'
    source.write_text("\n".join([shim, header, wrapper, "#define IV LSS_IV", lss, driver]))
    subprocess.run(['cc', '-std=c11', '-O2', '-I', str(args.urcrypt / 'blake3'), str(source),
                    str(args.urcrypt / 'blake3/blake3_portable.c'), '-o', str(binary)], check=True)
    cases = json.loads(subprocess.check_output([str(binary)]))
result = {'sources': {p.name: hashlib.sha256(p.read_bytes()).hexdigest() for p in
                     [lss_path, header_path, wrapper_path, args.urcrypt / 'blake3/blake3_portable.c']},
          'pattern': 'i % 29 >= 24 ? 0 : i % 251', 'cases': cases}
destination = Path(__file__).resolve().parents[1] / 'vectors/lss/vere.json'
if args.check:
    assert json.loads(destination.read_text()) == result, 'C source or fixture mismatch'
else:
    destination.write_text(json.dumps(result, indent=2) + '\n')
print(f'{len(cases)} C-built and C-verified LSS fixtures {"match" if args.check else "written"}')
