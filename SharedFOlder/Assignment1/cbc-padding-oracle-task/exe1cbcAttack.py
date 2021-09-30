import requests
import pprint
import json
# from flask import Flask, request, make_response, redirect, url_for
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto import Random
from secret_data import encryption_key, secret


_random_gen = Random.new()


url = 'http://localhost:5000'
urlSignRnd = 'http://localhost:5000/sign_random_document_for_students/'
urlSign = 'http://localhost:5000/sign'
urlVerify = 'http://localhost:5000/verify'
KEY_LENGTH = 16  # AES128
BLOCK_SIZE = AES.block_size



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

def pkcs7_padding(data):
    pkcs7 = True
    last_byte_padding = data[-1]
    if(last_byte_padding < 1 or last_byte_padding > 16):
        pkcs7 = False
    else:
        for i in range(0,last_byte_padding):
            if(last_byte_padding != data[-1-i]):
                pkcs7 = False
    return pkcs7

def oracle(encrypted):
    return pkcs7_padding(decrypt(encrypted))






cookie = requests.get(url)
# try to decode/decrypt the token
# print(cookie.text)
r1=cookie.cookies
authtoken=r1['authtoken']
print(authtoken)
print("this is space")
length=len(authtoken)

token = bytes.fromhex(r1['authtoken'])
print(token)
plaintext=decrypt(token)
print(plaintext)

print(pkcs7_padding(r1['authtoken']))



secondCooks = requests.get(url + '/quote/')
print(secondCooks.text)







# Get plain text from cookie
# Need padding for secret message
# Decrypt it and set it
# Set Cookie authtoken

