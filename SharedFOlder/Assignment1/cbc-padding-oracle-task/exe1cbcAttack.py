import requests
import pprint
import json
# from flask import Flask, request, make_response, redirect, url_for
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto import Random
from secret_data import encryption_key, secret

_random_gen = Random.new()
_key = _random_gen.read(KEY_LENGTH)

url = 'http://localhost:5000'
urlSignRnd = 'http://localhost:5000/sign_random_document_for_students/'
urlSign = 'http://localhost:5000/sign'
urlVerify = 'http://localhost:5000/verify'
KEY_LENGTH = 16  # AES128
BLOCK_SIZE = AES.block_size


r = requests.get(url, auth=('user','pass'))
r.status_code
r.encoding
r.text
r.json()

token = requests.get('authtoken')
# try to decode/decrypt the token
token = bytes.fromhex(token)






# Get plain text from cookie
# Decrypt it and set it
# Set Cookie authtoken

