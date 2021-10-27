import socket
import re
import time

HOST = '127.0.0.1'  # The server's hostname or IP address
PORT = 65432        # The port used by the server

while True:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        incrementVal = 0
        print("Connecting")
        s.connect((HOST, PORT))
        msg = "Increment this : " + str(incrementVal)
        print("Sending MSG")
        s.sendall(msg.encode())
        data = s.recv(1024)
        if not data:
            print("No data Received")
            break
        else:
            print("Received:", data)
            recvVal = data.decode("UTF-8")
            incVal = re.findall(r'\b\d+\b',recvVal)
            incrementVal = int(incVal[0]) + 1
            msg = "Increment this : " + str(incrementVal)
            print("Sending next message")
            time.sleep(2)
            s.sendall(msg.encode())




    if(incrementVal == 256):
        break

print('Received', repr(data))