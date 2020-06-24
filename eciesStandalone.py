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

ClientRSAkeyPair = RSA.generate(3072)

ClientRSAPublicKey = ClientRSAkeyPair.publickey()
print(f"Client RSA Public key:  (n={hex(ClientRSAPublicKey.n)}, e={hex(ClientRSAPublicKey.e)})")
ClientRSAPublicKeyPEM = ClientRSAPublicKey.exportKey()
print(ClientRSAPublicKeyPEM.decode('ascii'))

print(f"Client RSA Private key: (n={hex(ClientRSAPublicKey.n)}, d={hex(ClientRSAkeyPair.d)})")
ClientRSAPrivateKeyPEM = ClientRSAkeyPair.exportKey()
print(ClientRSAPrivateKeyPEM.decode('ascii'))

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

cv = Curve.get_curve("secp256k1")
g = cv.generator
p = cv.field
q = cv.order

# THIS HAPPENS IN THE BANK INTERNAL APP

bankPrivateECKey = 8922796882388619604127911146068705796569681654940873967836428543013949233636

bankPublicECKey = cv.mul_point(bankPrivateECKey, g)

# BANK  PUBLIC KEY IS SENT TO SGX, THIS HAPPENS IN SGX

ephimeralPrivateKey = 39224536263752937319809063883144929125312957084276525785186738781563829874778 # RANDOM GENERATED

AESSymmetricKey = cv.mul_point(ephimeralPrivateKey, bankPublicECKey).x

print("AES Key in hex:" + hex(AESSymmetricKey))

message = "Scoring A PLUS"

formatedAESSymmetricKey = hashlib.sha256(str(AESSymmetricKey).encode()).digest()

message = Padding.appendPadding(message,blocksize=Padding.AES_blocksize,mode=0)

ciphertext = encrypt(message.encode(),formatedAESSymmetricKey,AES.MODE_ECB) # Change this AES mode to a better one
ephimeralPublicKey = cv.mul_point(ephimeralPrivateKey, g) # TODO RSA

print("Credential CIPHERED VALUABLE FIELD:\t",binascii.hexlify(ciphertext))
print("Credential EPHEMERAL PUBLIC KEY:\t", hex(ephimeralPublicKey.x), hex(ephimeralPublicKey.y))

# CIPHERING WITH CLIENT'S RSA PUBLIC KEY THE EPHEMERAL PUBLIC KEY, STILL IN SGX


encryptor = PKCS1_OAEP.new(ClientRSAPublicKey)

clientCipheredEphimeralPublicKeyX = encryptor.encrypt(hex(ephimeralPublicKey.x))
clientCipheredEphimeralPublicKeyY = encryptor.encrypt(hex(ephimeralPublicKey.y))

print("Encrypted EPHEMERAL PUBLIC KEY WITH CLIENT PUBLIC KEY X:", binascii.hexlify(clientCipheredEphimeralPublicKeyX))
print("Encrypted EPHEMERAL PUBLIC KEY WITH CLIENT PUBLIC KEY Y:", binascii.hexlify(clientCipheredEphimeralPublicKeyY)) # CONTINUE HERE --> parse key to bytes


# END SGX, THIS HAPPENS IN BANK APP AFTER THE PAYMENT IS RECEIVED

AESSymmetricKeyPrime = cv.mul_point(bankPrivateECKey, ephimeralPublicKey).x

print("AES Key Prime in hex:" + hex(AESSymmetricKeyPrime))

# THIS HAPPENS IN THE SERVICE PROVIDER APP

formatedAESSymmetricKeyPrime = hashlib.sha256(str(AESSymmetricKeyPrime).encode()).digest()

text = decrypt(ciphertext,formatedAESSymmetricKeyPrime,AES.MODE_ECB)

print("Decrypted:\t",Padding.removePadding(text.decode(),mode=0))