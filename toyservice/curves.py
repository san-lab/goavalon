import argparse
import json
import hashlib
import binascii
from ecpy.curves import Curve, Point
from ecpy.keys import ECPublicKey, ECPrivateKey

from Crypto.Cipher import AES
import Padding


from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.IO import PEM


# msg = b'A message for encryption'
# encryptor = PKCS1_OAEP.new(pubKey)
# encrypted = encryptor.encrypt(msg)
# print("Encrypted:", binascii.hexlify(encrypted))

# decryptor = PKCS1_OAEP.new(keyPair)
# decrypted = decryptor.decrypt(encrypted)
# print('Decrypted:', decrypted)


def encrypt(plaintext,key, mode):
	encobj = AES.new(key,mode)
	return(encobj.encrypt(plaintext))

def decrypt(ciphertext,key, mode):
	encobj = AES.new(key,mode)
	return(encobj.decrypt(ciphertext))

def ppoint(point):
    print("x:",point.x)
    print("y:",point.y)

cv = Curve.get_curve("Ed25519")
g = cv.generator
p = cv.field
q = cv.order
halfp = p//2

def toProperKey(point):
    ybytes = point.y.to_bytes(32,'little')
    properpublickey = bytearray(ybytes)
    if point.x & 1:
          properpublickey[31] ^= 128
    return bytes(properpublickey)


bankPrivateECKey = 8922796882388619604127911146068705796569681654940873967836428543013949233636
bankPublicECKey = cv.mul_point(bankPrivateECKey, g)
#print("Bank public EC key(ED25519): ", bankPublicECKey)
#print("Compressed public key: ", toProperKey(bankPublicECKey).hex())


# BANK  PUBLIC KEY IS SENT TO SGX, THIS HAPPENS IN SGX

ephimeralPrivateKey = 39224536263752937319809063883144929125312957084276525785186738781563829874778 # RANDOM GENERATED

ss = cv.mul_point(ephimeralPrivateKey, bankPublicECKey)

print("p:", p)
print("q:", q)
print("g:")
ppoint(g)

g2 = cv.mul_point(2,g)
print("2g")
ppoint(g2)

g4 = cv.mul_point(4,g)
print("4g")
ppoint(g4)

g3 = cv.mul_point(3,g)
print("3g")
ppoint(g3)

g6 = cv.mul_point(6,g)
print("6g")
ppoint(g6)