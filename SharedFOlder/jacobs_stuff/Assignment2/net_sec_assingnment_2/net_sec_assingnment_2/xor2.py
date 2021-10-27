import sys

# Read the files as byte arrays
file1 = bytearray(open(sys.argv[1], 'rb').read())
file2 = bytearray(open(sys.argv[2], 'rb').read())

# Set the length to be the smaller one
size = len(file1) if len(file1) < len(file2) else len(file2)
xord_bytes = bytearray(size)

# XOR the files
for i in range(size):
    xord_bytes[i] = file1[i] ^ file2[i]

# Write the XOR bytes to new file1
open(sys.argv[3], 'wb').write(xord_bytes)

message = ''
for i in range(len(xord_bytes)):
    message = message + chr(xord_bytes[i])

print(message)
