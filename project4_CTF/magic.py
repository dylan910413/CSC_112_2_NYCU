#!/usr/bin/python
from pwn import *
import time
import random
from ctypes import CDLL
from ctypes.util import find_library

libc = CDLL(find_library("c"))
host = '140.113.24.241'
port = 30171
 
r = remote(host, port)

r.recvuntil(b'Please enter the secret:')
seed = int(time.time())
libc.srand(seed)

def generate_secret(seed):
    secret = ""
    for _ in range(16):
        secret += chr(48 + (libc.rand() % (126 - 47) + 1))
    return secret
secret = generate_secret(seed)
r.sendline(secret.encode())
r.recvline()
r.recvline()
print(r.recv().decode())
r.close()