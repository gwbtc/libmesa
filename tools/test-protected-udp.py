#!/usr/bin/env python3
"""Two independent libmesa processes: real UDP, signatures and LSS, exact bytes."""
import hashlib
from pathlib import Path
import socket
import subprocess

root=Path(__file__).resolve().parents[1]
subprocess.run(['cargo','build','-p','mesa-udp','--bin','protected-peer'],cwd=root,check=True)
binary=root/'target/debug/protected-peer'
for length in [0,1,1024,1025,17425,1048576]:
    reservations=[socket.socket(socket.AF_INET,socket.SOCK_DGRAM) for _ in range(2)]
    for sock in reservations: sock.bind(('127.0.0.1',0))
    addresses=[f'127.0.0.1:{sock.getsockname()[1]}' for sock in reservations]
    for sock in reservations: sock.close()
    processes=[]
    try:
        for i in range(2):
            processes.append(subprocess.Popen([str(binary),str(i+1),addresses[i],addresses[1-i],str(length)],stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True))
        for i,process in enumerate(processes):
            out,err=process.communicate(timeout=10)
            assert process.returncode==0,(out,err)
            remote=2-i
            data=bytes(0 if j%29>=24 else (j+remote)%251 for j in range(length))
            expected=f'peer={i+1} bytes={length} sha256={hashlib.sha256(data).hexdigest()} signature=verified lss=verified'
            assert out.strip()==expected,(out,expected)
        print(f'UDP: {length} exact bytes verified in both directions')
    finally:
        for process in processes:
            if process.poll() is None: process.kill()
            process.wait()
