import requests
import pprint
import json

url = 'http://localhost:5000'
urlSignRnd = 'http://localhost:5000/sign_random_document_for_students/'
urlSign = 'http://localhost:5000/sign'
urlVerify = 'http://localhost:5000/verify'
msg = 'myMessage.txt'

#r = requests.get(url)
#print("URL response is:%s"%r.text)

# Get the N and e from signer
#N, e = requests.get(url+'/pk')
#r = requests.get(url+'/pk')
#print("URL response is:%s"%r.text)
N = 4747617825483267073925707135434162140782004934969493398649736343767573386174499166941138646063220662821455140701644142359257329063942052795223317474678877110564110483218254880289977289048307199880402665029658877049360797459805835781627420432438712751798550418419105301405624143229561169600093588342146201784756880708600908928344572947609708337404639798662642244418650589116435961642768020203759429349403698698432185682705567949614107740794739651167165166624639079014899281603402085400692015050552763089958068944328032208666496558510713438122247268837627378178170946861723375422933830040547035303668584668126608258925462885979825374090528069149036275259663188199537520609654513129919337883970789966536969745290799935099950863921069116575446689497656227706052672735823896972693414633742125751405657219182268489315806491115129796661233116244966864621790834433702094798617364484880202219638327820815016545045384656338159947508201
e = 65537


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
#print("URL response is:%s"%r1.text)
r1 = json.loads(r1.text)
s1 = r1['signature']
s1_int = int(s1,16)
print(type(s1))
print(s1)
print(s1_int)
'''
# Create malecious message and make msg2 as product of this + first innocent msg
#evilMsg = 'Ill taker over the world now!'.encode('utf-8')
evilMsg = 'Gimmy 12!'#.encode('ascii')
evilMsg_int = [ord(ch) for ch in evilMsg]
evilMsg_int = int("".join(map(str, evilMsg_int)))
#print(evilMsg_int)  # 7110510910912132495033

#msg2 = int(evilMsg.hex(),16) / int(msg1.hex(),16)
msg2 = (evilMsg_int * (msg1_int^-1) ) % N

print(type(msg2))
print(msg2)
print(type(hex(msg2)))
print(hex(msg2))
m = str(msg2).encode('ascii')
print(type(m.hex()))
print(m.hex())

r2 = requests.get(urlSignRnd + m.hex() + '/')
print("URL response is:%s"%r2.text)

r2 = json.loads(r2.text)
s2 = r2['signature']

# From the two pairs m1/s1 and m2/s2 the signature for m can be extracted
s = s1*s2 % N
# IE. Alice just signed an evil msg !!!


r = requests.get(url+'/verify', evilMsg.hex(), s )
print(r)    # true/false
'''



#data = 0
#with open(msg, 'rb') as f:
#    r = requests.post(urlSign, files={msg: f})

#print("URL response is:%s"%r.text)