import requests
import pprint
import json
import math
from flask import Flask, request, make_response
from itertools import cycle
from copy import deepcopy, copy
from textwrap import wrap
import binascii
import base64
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from secret_data import encryption_key, secret
from oracle import encrypt, is_padding_ok, BLOCK_SIZE


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
# def xor(ba1, ba2):
#     return bytearray([ ba1[i] ^ ba2[i] for i in range(len(ba1)) ])


def xor(ba1,ba2):
    ba1=bytearray(ba1)
    ba2=bytearray(ba2)
    return bytearray([ ba1[i] ^ ba2[i] for i in range(len(ba1)) ])

def b2aPrint(ascii):
    print(binascii.b2a_hex(ascii))

def b2asPrint(ascii):
    print(binascii.b2a_hex((b''.join(ascii))))


def split_blocks(data):
    length = len(data)
    blocks = []
    for i in range(length / 16):
        blocks.append(data[i*16:(i+1)*16])
    return blocks

def decrypt(ciphertext: bytes) -> bytes:
    """Decrypt a ciphertext using our encryption key."""
    # the IV is stored in the first 16 B of the ciphertext
    iv = ciphertext[:16]
    aes = AES.new(encryption_key, AES.MODE_CBC, iv=iv)
    # decrypt the ciphertext
    plaintext = aes.decrypt(ciphertext[16:])
    # remove the padding of the plaintext
    message = unpad(plaintext, 16)
    return message

def find_bytes(blocks):

    blockSize=8
    
    c_prime = bytearray([b for b in blocks[0]])
    plaintext_bytes = bytearray([0 for _ in range(16)])
    expectedPadding=bytearray(8)
    for i in range(16):

        for o in range(blockSize):
            if o < (blockSize-1-i):
                expectedPadding[o] = 0
            else:
                expectedPadding[o] = i+1

        c_prime = xor(xor(expectedPadding, plaintext_bytes), blocks[0])
        print(c_prime)
        # for byte in range(blocks[0][15]+1,256) + range(0, blocks[0][15]+1):
        for byte in range(0,256):
            # c_prime=1
            c_prime[15-i]=byte
            to_test = base64.b64decode(str(c_prime+blocks[1]))


            try:
                decrypt(to_test)
                plaintext_bytes[15-i]=(byte^(i+1)^blocks[0][15-i])
                break
            except:
                pass

    return ''.join([chr(b) for b in plaintext_bytes if b>16])

def find_plaintext(url):
    session = requests.Session()
    r = session.get(url)
    curAuthToken = session.cookies.get_dict()['authtoken']
    # print(curAuthToken)
    ciphertext = (curAuthToken.encode('utf-8'))
    # print(ciphertext)
    # ciphertext = binascii.a2b_hex(ciphertext)

    Newciphertext = bytearray(base64.b64decode(curAuthToken))
    blocks = splitLen(Newciphertext, 8)
    plaintext = ''

    for i in range(len(blocks)-1):
        plaintext += find_bytes(blocks[i:i+1])

    print(plaintext)



def attack_message(msg):

    cipherfake=[0] * 16
    plaintext = [0] * 16
    current = 0
    message=""


    #I devide the list of bytes in blocks, and I put them in another list
    number_of_blocks = int(len(msg)/BLOCK_SIZE)
    blocks = [[]] * number_of_blocks
    for i in (range(number_of_blocks)):
        blocks[i] = msg[i * BLOCK_SIZE: (i + 1) * BLOCK_SIZE]

    for z in range(len(blocks)-1):  #for each message, I calculate the number of block
        for itera in range (1,17): #the length of each block is 16. I start by one because than I use its in a counter
            for v in range(256):
                cipherfake[-itera]=v
                if is_padding_ok(bytes(cipherfake)+blocks[z+1]): #the idea is that I put in 'is_padding_ok' the cipherfake(array of all 0) plus the last block
                                                                 #if the function return true I found the value
                    current=itera
                    plaintext[-itera]= v^itera^blocks[z][-itera]

            for w in range(1,current+1):
                cipherfake[-w] = plaintext[-w]^itera+1^blocks[z][-w] #for decode the second byte I must set the previous bytes with 'itera+1'


        for i in range(16):
            if plaintext[i] >= 32:
                char = chr(int(plaintext[i]))
                
                message += char
    
    print("Crack: " + decrypt(message) + "\n")
    return str.encode(message)

find_plaintext(url)


# session = requests.Session()
# r = session.get(url)
# curAuthToken = session.cookies.get_dict()['authtoken']
# # print(curAuthToken)
# ciphertext = (curAuthToken.encode('utf-8'))
# # print(ciphertext)
# ciphertext = binascii.a2b_hex(ciphertext)


# print(attack_message(ciphertext).decode())


# ### Start session - get authentication token
# session = requests.Session()
# r = session.get(url)
# curAuthToken = session.cookies.get_dict()['authtoken']
# #print(curAuthToken)

# ciphertext = (curAuthToken.encode('utf-8'))
# ciphertext = binascii.a2b_hex(ciphertext)
# #print(ciphertext)

# ### Definitions
# blockSize = 8       # 8 bytes

# # split authentication token into block sizes
# blocks = splitLen(ciphertext, blockSize)
# ### b2asPrint(blocks)

# n_blocks = len(blocks)
# #print("n_blocks: "+str(n_blocks))

# blocksCopy = [row[:] for row in blocks]             # imutable
# curBlock = bytearray([b for b in blocksCopy[0]])    # mutable
# #print("curblock: ", end='')
# #print(binascii.b2a_hex(curBlock))







# # To store plaintext
# plaintextBytes = bytearray(blockSize)
# # To store padding for xor'ing
# expectedPadding = bytearray(blockSize)


# ### Iterate through bytes in block
# for bytePos in range(0,blockSize):

#     # Initiate right padding for byte-pos
#     for i in range(blockSize):
#         if i < (blockSize-1-bytePos):
#             expectedPadding[i] = 0
#         else:
#             expectedPadding[i] = bytePos+1
    
#     # calculate curBlock for future attempts IE. right padding
#     curBlock = xor(xor(expectedPadding,plaintextBytes),curBlock)
#     # expPad (+) curBlock = plaintext
#     # plaintext (+) plaintext = zero IE. remove from future calculations


#     ### try every pad-size - see when it doesn't fail!
#     for byte in range(0, 256):       

#         curBlock[blockSize-1-bytePos] = byte


# # WRONG
#         if(bytePos != 0):
#             curBlock[blockSize-bytePos] = plaintextBytes[bytePos]
#         #print(binascii.b2a_hex(curBlock))

        

#         # test padding response
#         blocksCopy[0] = curBlock
#         res = getResponse(blocksCopy)
#         #print(res)
#         if(res == b'No quote for you!'): # IE. the padding fits !!!
#             # b2asPrint(blocks)
#             # b2asPrint(blocksCopy)
#             # b2aPrint(curBlock)
            
#             byte = "{:02x}".format(byte).encode('utf-8')
#             mask = "{:02x}".format(bytePos+1).encode('utf-8')
#             curVal = "{:02x}".format(curBlock[blockSize-1-bytePos]).encode('utf-8')
#             # print(byte)
#             # print(mask)
#             # print(curVal)

#             #print(byte ^ mask ^ curVal)
#             res1 = xor(mask, byte)
#             #print(res1)
#             res2 = xor(curVal, bytearray(res1))
#             plaintextBytes[blockSize-1-bytePos] = int(res2)
#             break
#     #print(expectedPadding)




# print("Plaintext: ")
# print(plaintextBytes)
