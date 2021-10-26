from socket import *
import threading
import sys
import random
import string
import os


def handle_connection(client, client_address):
    print("connection from address: {!s}".format(client_address))

    msg_type_bytes = client.recv(1)
    msg_type = int.from_bytes(msg_type_bytes, byteorder=sys.byteorder)

    msg_size_bytes = client.recv(msg_type - 1)
    msg_size = int.from_bytes(msg_size_bytes, byteorder=sys.byteorder)

    print("msg size: {}".format(msg_size))
    data = client.recv(msg_size)
    if msg_type == 1:
        print(data)
    else:
        filename = write_file(data)
        print("saved bytes to file: {}".format(filename))

    client.sendall(data)

    client.close()


def write_file(data, filename=None):
    if not filename:
        filename_length = 8
        filename = "".join([random.SystemRandom().choice(
            string.ascii_letters + string.digits) for n in range(filename_length)])

        filename += ".bin"

        try:
            with open("./" + filename, "wb") as f:
                f.write(data)
        except EnvironmentError as e:
            print("error writing file: {}".format(e))
            return None

        return filename


def main():
    server = socket(AF_INET, SOCK_STREAM)

    port = 9000
    server.bind(("localhost", port))

    server.listen(5)
    print("server listening on: {!s}".format(port))

    while True:
        (client, address) = server.accept()

        client_thread = threading.Thread(
            target=handle_connection, args=(client, address))

        client_thread.start()


if __name__ == "__main__":
    main()
