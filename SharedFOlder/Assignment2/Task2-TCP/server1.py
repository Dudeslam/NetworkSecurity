import socket
import re
import time

# HOST = '192.168.0.7' # IPV4 address
# HOST = '192.168.0.1' #DEfault gateway
HOST = '127.0.0.1'  # Standard loopback interface address (localhost)
PORT = 65432        # Port to listen on (non-privileged ports are > 1023)

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    s.bind((HOST, PORT))
    print("Waiting for connection")
    s.listen()
    conn, addr = s.accept()
    with conn:
        print('Connected by', addr)
        while True:
            data = conn.recv(1024)
            
            if not data:
                print("No data Received")
                break
            else:
                print("Received:", data)
                recvVal = data.decode("UTF-8")
                incVal = re.findall(r'\b\d+\b',recvVal)
                returnVal = "Value to send Back: " + str(incVal[0])
                print(returnVal)
                time.sleep(2)
                try:
                    conn.sendall(returnVal.encode())
                except:
                    print("Could not send message")