from http import cookiejar
import requests
import pprint
import json
import math
from requests.cookies import create_cookie
import base64
from requests.sessions import RequestsCookieJar
from secret_data import rsa_key
from flask import Flask, Request, make_response, Response, jsonify
from http.cookiejar import CookieJar


url = 'https://rsa.syssec.lnrd.net/grade/'
urlSignRnd = 'https://rsa.syssec.lnrd.net/sign_random_document_for_students/'
urlSign = 'https://rsa.syssec.lnrd.net/sign'
urlVerify = 'https://rsa.syssec.lnrd.net/verify'
msg = 'myMessage.txt'


#r = requests.get(url)
#print("URL response is:%s"%r.text)

# Get the N and e from signer
#N, e = requests.get(url+'/pk')
#r = requests.get(url+'/pk')
#print("URL response is:%s"%r.text)
N = 4747617825483267073925707135434162140782004934969493398649736343767573386174499166941138646063220662821455140701644142359257329063942052795223317474678877110564110483218254880289977289048307199880402665029658877049360797459805835781627420432438712751798550418419105301405624143229561169600093588342146201784756880708600908928344572947609708337404639798662642244418650589116435961642768020203759429349403698698432185682705567949614107740794739651167165166624639079014899281603402085400692015050552763089958068944328032208666496558510713438122247268837627378178170946861723375422933830040547035303668584668126608258925462885979825374090528069149036275259663188199537520609654513129919337883970789966536969745290799935099950863921069116575446689497656227706052672735823896972693414633742125751405657219182268489315806491115129796661233116244966864621790834433702094798617364484880202219638327820815016545045384656338159947508201
e = 65537


def verify(message: bytes, signature: bytes) -> bool:
    """Verify a signature using our public key."""
    # modulus and private exponent
    #N = rsa_key['_n']
    #e = rsa_key['_e']
    # interpret the bytes of the message and the signature as integers stored
    # in big-endian byte order
    m = int.from_bytes(message, 'big')
    s = int.from_bytes(signature, 'big')
    if not 0 <= m < N or not 0 <= s < N:
        raise ValueError('message or signature too large')
    # verify the signature
    mm = pow(s, e, N)
    return m == mm

def json_to_cookie(j: str) -> str:
    """Encode json data in a cookie-friendly way using base64."""
    # The JSON data is a string - encode it into bytes
    json_as_bytes = j.encode()
    # base64-encode the bytes
    base64_as_bytes = base64.b64encode(json_as_bytes, altchars=b'-_')
    # b64encode returns bytes again, but we need a string - decode it
    base64_as_str = base64_as_bytes.decode()
    return base64_as_str


# Get first "innocent" message signed
#msg1 = 'my message 1, plz sign'.encode('ascii')
#print('msg1: '+msg1.hex())
#r1 = requests.get(urlSignRnd + msg1.hex() + '/')

msg1 = 'my message 1, plz sign'
msg1_int = [ord(ch) for ch in msg1]
msg1_int = int("".join(map(str, msg1_int)))
#print(msg1_int)                         # 10912132109101115115971031013249443211210812232115105103110
#print(type(msg1.encode('ascii').hex()))
#print(msg1.encode('ascii').hex())

r1 = requests.get(urlSignRnd + msg1.encode('ascii').hex() + '/')
firstCook=r1.cookies
# print("first cookie")
# print("URL response is:%s"%r1.text)
r1 = json.loads(r1.text)

msg1_b = bytes.fromhex(r1['msg'])
#print(msg.decode())                        # decode goes from byte array to str
sig1_b = bytes.fromhex(r1['signature'])
res1 = verify(msg1_b, sig1_b)
#print('Result: ', res1)
sig1_int = int(sig1_b.hex(),16)
#print(sig1_int)




# Create malecious message and make msg2 as product of this + first innocent msg
#evilMsg = 'Ill taker over the world now!'.encode('utf-8')
# evilMsg = 'Gimmy 12'            #.encode('ascii')
evilMsg = 'You got a 12 because you are an excellent student! :)'
evilMsg_int = [ord(ch) for ch in evilMsg]
evilMsg_int = int("".join(map(str, evilMsg_int)))
#print(evilMsg_int)  # 7110510910912132495033


# Extended GCD
def egcd(a, b):
    if a == 0:
        return (b, 0, 1)
    else:
        g, y, x = egcd(b % a, a)
        return (g, x - (b // a) * y, y)

# Calculated inverse modular m
def modinv(a, m):
    g, x, y = egcd(a, m)
    if g != 1:
        raise Exception('modular inverse does not exist')
    else:
        return x % m


# Verifying modinv
#print( (modinv(msg1_int,N)*msg1_int)%N )
#print('HERE')


#msg2 = int(evilMsg.hex(),16) / int(msg1.hex(),16) % N
msg2 = (evilMsg_int * modinv(msg1_int,N) ) % N
#print(type(hex(msg2)[2:]))
#print(hex(msg2)[2:])

r2 = requests.get(urlSignRnd + hex(msg2)[2:] + '/')
#print("URL response is:%s"%r2.text)
r2 = json.loads(r2.text)
print(r2)


msg2_b = bytes.fromhex(r2['msg'])
#print(msg.decode())                        # decode goes from byte array to str
sig2_b = bytes.fromhex(r2['signature'])
res2 = verify(msg2_b, sig2_b)
#print('Result: ', res2)
sig2_int = int(sig2_b.hex(),16)
#print(sig2_int)


#s2 = r2['signature']
#s2_int = int(s2,16)
#print(type(s2))
#print(s2)


# From the two pairs m1/s1 and m2/s2 the signature for m can be extracted
sigEvil_int = (sig1_int*sig2_int) % N
#sigEvil_hex = hex(sigEvil_int)[2:].zfill(2)
sigEvil_hex = sigEvil_int.to_bytes(((sigEvil_int.bit_length() + 7) // 8),"big").hex()
#print(sigEvil_hex)
sigEvil_b = bytes.fromhex(sigEvil_hex)
msgEvil_b = evilMsg.encode()
#print(sigEvil_b)
#print(msgEvil_b)

res3 = verify(msgEvil_b, sigEvil_b)
print('Result: ', res2)
# IE. Alice just signed an evil msg !!!


#cookies = dict({'msg': msgEvil_b, 'signature': sigEvil_b})
cookay = dict({'msg': evilMsg.encode('ascii').hex(), 'signature': hex(sigEvil_int)[0][2:]})
#r = requests.get(url+'grade/', cookies=cookies)

# print(bytes.fromhex(cookay['msg']))
# print('this is space')
# print(bytes.fromhex(cookay['signature']))

# print(cookay.key)

r1 = requests.get(url+'grade/')
print("URL response is:%s"%r1.text)

print(r1.cookies)

print("space to seperate")
j = json.dumps({'msg': evilMsg.encode('ascii').hex(), 'signature': hex(sigEvil_int)[0][2:]})
# Cooks=json_to_cookie(j)


r1.cookies.clear()
# r1.cookies['msg']=evilMsg.encode('ascii').hex()
# r1.cookies['signature']=hex(sigEvil_int)[2:]
r1.cookies.set('grade',j)
print(r1.cookies)

# finalCooks=create_cookie('grade',j)

# getcook = r1.cookies.get('grade')

# print(getcook)
# print(getcook['signature'])


# r2 = requests.get(url+'quote/', cookies=firstCook)
r2 = requests.get(url+'quote/', cookies=r1.cookies)
print("URL response is:%s"%r2.text)


# j = json.dumps({'msg': evilMsg.encode('ascii').hex(), 'signature': hex(sigEvil_int)[2:]})
# # response = make_response('You got a 12 because you are an excellent student! :)')
# set_cookie('grade', j)
# r = requests.get(url+'quote/')



