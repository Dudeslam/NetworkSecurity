import socket
import re
import time
import sys

# HOST = '192.168.0.7'  # The server's hostname or IP address
# HOST = '127.0.0.1'  # Standard loopback interface address (localhost)
HOST = '192.168.0.26' # IPV4 Laptop
PORT = 65432        # The port used by the server




with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    incrementVal = 0
    print("Connecting")
    try:
        s.connect((HOST, PORT))
    except:
        s.close()
        print("Could not create connection")

    try:  
        msg = "Increment this : " + str(incrementVal)
        print("Sending MSG")
        s.sendall(msg.encode())
    except:
        s.close()
        print("could not send data, now closing connection")
        sys.exit()


    data = s.recv(1024)
    while True:
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
            try:
                s.sendall(msg.encode())
            except:
                s.close()
                print("could not send data, now closing connection")
                sys.exit()
        



