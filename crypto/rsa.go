package crypto

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"crypto/rand"
	"crypto/sha1"
)

//The input string is assumed to be PEM formatted
func ParseRSAPublicKey(pubPEM string) (*rsa.PublicKey, error) {

	block, _ := pem.Decode([]byte(pubPEM))
	if block == nil {
		return nil, fmt.Errorf("Could not decode the key")
	}

	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, err
	}

	switch pub := pub.(type) {
	case *rsa.PublicKey:
		return pub, nil
	default:
		return nil, fmt.Errorf("unknown type of public key")
	}

}

//The input string is assumed to be PEM formatted
func ParseRSAPrivateKey(privPEM string) (*rsa.PrivateKey, error) {
	block, _ := pem.Decode([]byte(privPEM))
	if block == nil {
		return nil, fmt.Errorf("Could not decode the key")
	}

	priv, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	return priv, nil

}


//We encrypt with sha256 hash and NO LABEL
func EncryptWithRSAKey(plaintext []byte, key *rsa.PublicKey) ([]byte, error) {

	b, e := rsa.EncryptOAEP(sha1.New(), rand.Reader, key, plaintext, nil)
	if e != nil {
		return nil, e
	}

	return b, nil
}
