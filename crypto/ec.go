package crypto

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/pem"
	"github.com/btcsuite/btcd/btcec"
)

var ecPubKeyPreamble = []byte{48, 86, 48, 16, 6, 7, 42, 134, 72, 206, 61, 2, 1, 6, 5, 43, 129, 4, 0, 10, 3, 66, 0}

func ParseKoblitzPubPem(pemstring string) (*btcec.PublicKey, error) {
	blk, _ := pem.Decode([]byte(pemstring))
	return btcec.ParsePubKey(blk.Bytes[len(ecPubKeyPreamble):], btcec.S256())

}

func DecodeECSignature(signaturestring string) (*btcec.Signature, error) {

	ccsignature, err := hex.DecodeString(signaturestring)
	if err != nil {
		return nil, err
	}

	return btcec.ParseSignature(ccsignature, btcec.S256())
}

//Verifies signature of a string.
//We assume that the string is treated as UTF-8 bytes
func VerifySignatureOfString(text string, signature *btcec.Signature, key *btcec.PublicKey) bool {
	hash := sha256.New()
	h := hash.Sum([]byte(text))
	return signature.Verify(h, key)
}
