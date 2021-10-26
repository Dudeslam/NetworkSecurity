from socket import *
import sys
import os


def main():
    while not input("enter to connect to server"):

        val = input("1 for string, 2 for bytes")
        msg = int(val).to_bytes(length=1, byteorder=sys.byteorder)

        if val == "1":
            text = input("Enter your message")
            msg = msg + bytes(text, "utf-8")
        else:
            size = 0
            if val == "2":
                size = 100
            if val == "3":
                size = 1000
            if val == "4":
                size = 100000
            random_array = bytearray(os.urandom(size))
            msg_length_bytes = int(size).to_bytes(
                length=int(val) - 1, byteorder=sys.byteorder)
            msg = msg + msg_length_bytes + random_array

        client = socket(AF_INET, SOCK_STREAM)
        port = 9000

        client.connect(("192.168.0.30", port))

        print("sending when connected")

        client.send(msg)
        data = client.recv(1024)

        print("data: {!s}".format(data))
        client.close()
        print("client connection closed")


if __name__ == "__main__":
    main()
