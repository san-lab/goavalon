from Crypto.Cipher import AES
import base64


def decrypt(key, ciphertext: bytes) -> bytes:
        """Return plaintext for given ciphertext."""

        # Split out the nonce, tag, and encrypted data.
        nonce = ciphertext[:12]
        if len(nonce) != 12:
            raise DataIntegrityError("Cipher text is damaged: invalid nonce length")

        tlen = len(ciphertext) - 16
        if tlen < 12:
            raise DataIntegrityError("Cipher text is damaged: too short")

        encrypted = ciphertext[12: tlen]
        tag = ciphertext[tlen:]
        if len(tag) != 16:
            raise DataIntegrityError("Cipher text is damaged: invalid tag length")

        # Construct AES cipher, with old nonce.
        cipher = AES.new(key, AES.MODE_GCM, nonce)

        # Decrypt and verify.
        try:
            plaintext = cipher.decrypt_and_verify(encrypted, tag)  # type: ignore
        except ValueError as e:
            raise DataIntegrityError("Cipher text is damaged: {}".format(e))
        return plaintext

hexkey = "81d50c9eb7f929ba8923f9fb419a51364181bd7791d96d869251486611d29bc4"

base64cipher = "ateM3GyyHZ7Li2YlaigTGDeKyZlMPuLzPaMwLO8QJeJbVQ=="

bkey = bytes.fromhex(hexkey)

bcipher = base64.b64decode(base64cipher)

plainbytes = decrypt(bkey, bcipher)
plaintext = str(plainbytes, "utf-8")
print(plaintext)
