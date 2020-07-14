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




#IssuerPublicKey = "6cc0580343356515c288897c68dad03a2063d1ea9c03c14af40174bef52d1503"
#IssuerSignature = "acd34a616765820fe6c57ff1ddcbcbed55667e141b99aa2e86f723e16060407a260bc1b4e61e0d763f025550ede2f65e2f87d348adfc9da9b81ded7d33f62008"
#Message =  "Przemek"+"333"+"Average account balance cert"+"25001 EUR"+"0042"
#
#v = verify(Message, IssuerPublicKey, IssuerSignature)
#print("Signature valid:", v)

seed = bytes([0x00, 0x00, 0x00, 0x00,0x00, 0x00, 0x00, 0x00,0x00, 0x00, 0x00, 0x00,0x00, 0x00, 0x00, 0x00,0x00, 0x00, 0x00, 0x00,0x00, 0x00, 0x00, 0x00,0x00, 0x00, 0x00, 0x00,0x00, 0x00, 0x00, 0x02])
privkey = generateFromSeed(seed)
privKey_bytes = bytes(privkey)
privKey_hex = privKey_bytes.hex()
print(privkey[:32])
print(privkey[32:])
print(privKey_hex)


