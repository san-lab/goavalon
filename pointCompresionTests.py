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

cv = Curve.get_curve("Ed25519")
g = cv.generator
p = cv.field
q = cv.order
halfp = p//2

def toProperKey(point):
    ybytes = point.y.to_bytes(32, 'little')
    properpublickey = bytearray(ybytes)
    if point.x < halfp:
        properpublickey[31] ^= 128
    return bytes(properpublickey)

bankPrivateECKey = 8922796882388619604127911146068705796569681654940873967836428543013949233689 # SWAP, recover with 1
bankPrivateECKey2 = 8922796882388619604127911146068705796569681654940873967836428543013949233637 # SWAP, recover with 0
bankPrivateECKey3 = 8922796882388619604127911146068705796569681654940873967836428543013949233636 # NO SWAP, recover with 0
bankPublicECKey = cv.mul_point(bankPrivateECKey, g)
print("Bank public EC key(ED25519): ", bankPublicECKey)
print("Compressed public key: ", toProperKey(bankPublicECKey).hex())

pointCompressed = cv.encode_point(bankPublicECKey).hex()

print("Compresed point with ec method: ", pointCompressed)

pointBack = cv.decode_point(bytearray.fromhex(pointCompressed))

print("Decompressed point with ec method: ", pointBack)

print(toProperKey(bankPublicECKey)[31] & 128)
print(hex(cv.x_recover(bankPublicECKey.y, 1)))

####

bankPublicECKey = cv.mul_point(bankPrivateECKey2, g)
print("Bank public EC key(ED25519): ", bankPublicECKey)
print("Compressed public key: ", toProperKey(bankPublicECKey).hex())
print("Compresed point with ec method: ", cv.encode_point(bankPublicECKey).hex())


print(toProperKey(bankPublicECKey)[31] & 128)
print(hex(cv.x_recover(bankPublicECKey.y, 0))) # This one should be 1

####

bankPublicECKey = cv.mul_point(bankPrivateECKey3, g)
print("Bank public EC key(ED25519): ", bankPublicECKey)
print("Compressed public key: ", toProperKey(bankPublicECKey).hex())
print("Compresed point with ec method: ", cv.encode_point(bankPublicECKey).hex())

print(toProperKey(bankPublicECKey)[31] & 128)
print(hex(cv.x_recover(bankPublicECKey.y, 0)))
