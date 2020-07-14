import hashlib
from ecpy.curves import Curve, Point
from ecpy.keys import ECPublicKey, ECPrivateKey

cv = Curve.get_curve("Ed25519")
g = cv.generator
p = cv.field
l = cv.order

#message as a string
#pbkey as a point encoded as hexstring (32)
#signature as hexstring
def verify(message, pbkey, signature):
    # sign contains R i s (32 bytes each)
    # Verify:
    # R + hash(R+m)Pb == sG
    keybytes =  bytes.fromhex(pbkey)
    sigbytes = bytes.fromhex(signature)
    R = sigbytes[:32]
    s = sigbytes[32:]

    #calculate the hash
    h = hashlib.sha256()
    h.update(R)
    h.update(message.encode("utf-8"))

    hint = int.from_bytes(h.digest(),"little")


    si = int.from_bytes(s, "little")
    S = cv.mul_point(si,g)

    Rp = cv.decode_point(R)
    Pb = cv.decode_point(keybytes)
    X = cv.add_point(Rp, cv.mul_point(hint, Pb))
    # R + hash(R+m)Pb == sGoh sure sure
    return (X.eq(S))


def generateFromSeed(seed):
#TODO verify that the seed is 32 bytes
    h = hashlib.sha512()
    h.update(seed)
    dig64 = h.digest()

    #clamp
    dig64_barray = bytearray(dig64)

    dig64_barray[0] &= 248
    dig64_barray[31] &= 127
    dig64_barray[31] |= 64

    bytes_d64 = bytes(dig64_barray)

    dint = int.from_bytes(bytes_d64[:32], "little")

    pubPoint = cv.mul_point(dint,g)
    privkey = seed + cv.encode_point(pubPoint)

    return privkey

#pubKey is byte32
#message is bytes 32
#signature is bytes 64
def verifyEd(pubKey, message, signature):
    R = signature[:32]
    R_point = cv.decode_point(R)

    s = signature[32:]
    s_int = int.from_bytes(s,"little")
    s_point= cv.mul_point(s_int,g)
    
    h = hashlib.sha512()
    h.update(R + pubKey + message)
    x = h.digest()
    x_int = int.from_bytes(x, "little")
    
    A = cv.decode_point(pubKey)
    P1 = cv.mul_point(x_int,A)

    S_prime = cv.add_point(P1,R_point)

    return s_point.eq(S_prime)

#privKey is byte64
#message is bytes
def signEd(privKey, message):
    seed = privKey[:32]
    pubKey = privKey[32:]

    h = hashlib.sha512()
    h.update(seed)
    nonce = h.digest()[32:]

    h = hashlib.sha512()
    h.update(nonce+message)
    r = h.digest()
    r_int = int.from_bytes(r,"little")
    R = cv.mul_point(r_int,g)
    R_encoded = cv.encode_point(R)

    h = hashlib.sha512()
    h.update(R_encoded+pubKey+message)
    h_scalar = h.digest()
    int_h_scalar = int.from_bytes(h_scalar,"little")

    nonce_barray = bytearray(nonce)

    nonce_barray[0] &= 248
    nonce_barray[31] &= 127
    nonce_barray[31] |= 64

    bytes_nonce = bytes(nonce_barray)
    int_nonce = int.from_bytes(bytes_nonce, "little")

    int_s = (r_int + int_h_scalar*int_nonce) % l
    #s_bytes = int_s.to_bytes(32, "little")
    s_bytes = bytes(int_s)

    return R_encoded + s_bytes



#IssuerPublicKey = "6cc0580343356515c288897c68dad03a2063d1ea9c03c14af40174bef52d1503"
#IssuerSignature = "acd34a616765820fe6c57ff1ddcbcbed55667e141b99aa2e86f723e16060407a260bc1b4e61e0d763f025550ede2f65e2f87d348adfc9da9b81ded7d33f62008"
#Message =  "Przemek"+"333"+"Average account balance cert"+"25001 EUR"+"0042"
#
#v = verify(Message, IssuerPublicKey, IssuerSignature)
#print("Signature valid:", v)


#Testing generate from seed
seed = bytes([0x00, 0x00, 0x00, 0x00,0x00, 0x00, 0x00, 0x00,0x00, 0x00, 0x00, 0x00,0x00, 0x00, 0x00, 0x00,0x00, 0x00, 0x00, 0x00,0x00, 0x00, 0x00, 0x00,0x00, 0x00, 0x00, 0x00,0x00, 0x00, 0x00, 0x02])
privkey = generateFromSeed(seed)
privKey_bytes = bytes(privkey)
privKey_hex = privKey_bytes.hex()
pub_key = privkey[32:]
#print(privkey[:32])
#print(privkey[32:])
#print(privKey_hex)

#signing message 'Avalon'
#13e37be0bde224336d144ee13ec68fbf21994ea3124a4616bfaf9e88e9203c8808f036a8fcce8df201cf26c8f4c5a2d8c2a780fec64b60caa519e8b310490f0e

hex_signature = "13e37be0bde224336d144ee13ec68fbf21994ea3124a4616bfaf9e88e9203c8808f036a8fcce8df201cf26c8f4c5a2d8c2a780fec64b60caa519e8b310490f0e"
bytes_sig = bytes.fromhex(hex_signature)
message_bytes = "Avalon".encode('utf-8')
#print(bytes_sig)
#print(message_bytes)

result = verifyEd(pub_key, message_bytes, bytes_sig)
#print(result)

new_sig = signEd(privKey_bytes, message_bytes)
print(bytes_sig.hex())
print(new_sig.hex())

result2 = verifyEd(pub_key, message_bytes, new_sig)
print(result2)




