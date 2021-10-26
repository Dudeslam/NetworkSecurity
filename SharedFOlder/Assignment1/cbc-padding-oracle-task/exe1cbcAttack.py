import requests
import pprint
import json
import math
from flask import Flask, request, make_response
from itertools import cycle
from copy import deepcopy, copy
from textwrap import wrap
import binascii

#url = 'https://cbc.syssec.lnrd.net/'
url = 'http://localhost:5000/'
urlQuote = url+'quote/'

# You are given the source code of a simple website that distributed quotes.
# However, you only receive a quote if you can present a cookie containing a
# valid authentication token.  Such a token is an AES-CBC encryption of a certain
# message.

# You first need to recover the secret part of the message, and then create a valid
# ciphertext containing the right plaintext without having access to the
# encryption key.

# This requires you to exploit the properties of the CBC mode of encryption,
# together with the fact that the service outputs helpful error messages in case
# something goes wrong.


# Used to split authentication token into an array of 16bit blocks
def splitLen(seq, length):
    return [seq[i : i + length] for i in range(0, len(seq), length)]

def getResponse(cipher):
    #token = binascii.b2a_hex((b''.join(cipher[::-1])))
    token = binascii.b2a_hex((b''.join(cipher)))
    #print(token.decode())
    cookies_dict = {"authtoken": token.decode()}
    response = requests.get(urlQuote, cookies=cookies_dict)
    return response.content

# Xors two byte arrays
def xor(ba1, ba2):
    return bytearray([ ba1[i] ^ ba2[i] for i in range(len(ba1)) ])

def b2aPrint(ascii):
    print(binascii.b2a_hex(ascii))

def b2asPrint(ascii):
    print(binascii.b2a_hex((b''.join(ascii))))








### Start session - get authentication token
session = requests.Session()
r = session.get(url)
curAuthToken = session.cookies.get_dict()['authtoken']
#print(curAuthToken)

ciphertext = (curAuthToken.encode('utf-8'))
ciphertext = binascii.a2b_hex(ciphertext)
#print(ciphertext)

### Definitions
blockSize = 8       # 8 bytes

# split authentication token into block sizes
blocks = splitLen(ciphertext, blockSize)
### b2asPrint(blocks)

n_blocks = len(blocks)
#print("n_blocks: "+str(n_blocks))

blocksCopy = [row[:] for row in blocks]             # imutable
curBlock = bytearray([b for b in blocksCopy[0]])    # mutable
#print("curblock: ", end='')
#print(binascii.b2a_hex(curBlock))







# To store plaintext
plaintextBytes = bytearray(blockSize)
# To store padding for xor'ing
expectedPadding = bytearray(blockSize)


### Iterate through bytes in block
for bytePos in range(0,blockSize):

    # Initiate right padding for byte-pos
    for i in range(blockSize):
        if i < (blockSize-1-bytePos):
            expectedPadding[i] = 0
        else:
            expectedPadding[i] = bytePos+1
    
    # calculate curBlock for future attempts IE. right padding
    curBlock = xor(xor(expectedPadding,plaintextBytes),curBlock)
    # expPad (+) curBlock = plaintext
    # plaintext (+) plaintext = zero IE. remove from future calculations


    ### try every pad-size - see when it doesn't fail!
    for byte in range(0, 256):       

        curBlock[blockSize-1-bytePos] = byte


# WRONG
        if(bytePos != 0):
            curBlock[blockSize-bytePos] = plaintextBytes[bytePos]
        #print(binascii.b2a_hex(curBlock))

        

        # test padding response
        blocksCopy[0] = curBlock
        res = getResponse(blocksCopy)
        #print(res)
        if(res == b'No quote for you!'): # IE. the padding fits !!!
            # b2asPrint(blocks)
            # b2asPrint(blocksCopy)
            # b2aPrint(curBlock)
            
            byte = "{:02x}".format(byte).encode('utf-8')
            mask = "{:02x}".format(bytePos+1).encode('utf-8')
            curVal = "{:02x}".format(curBlock[blockSize-1-bytePos]).encode('utf-8')
            # print(byte)
            # print(mask)
            # print(curVal)

            #print(byte ^ mask ^ curVal)
            res1 = xor(mask, byte)
            #print(res1)
            res2 = xor(curVal, bytearray(res1))
            plaintextBytes[blockSize-1-bytePos] = int(res2)
            break
    #print(expectedPadding)




print("Plaintext: ")
print(plaintextBytes)
