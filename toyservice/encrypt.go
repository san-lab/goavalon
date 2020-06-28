package toyservice

import (
	"crypto/rsa"
	"golang.org/x/crypto/ed25519"
)

func EncryptScoring(erq *EncryptRequest) (*Scoring, error) {
	var issuerPubKey *ed25519.PublicKey
	var clientPubKey *rsa.PublicKey
	issuerPubKey, _ = decodeIssuerKey(erq.Issuerpubkey)
	clientPubKey, _ = decodeClientKey(erq.Issuerpubkey)

	secret, lockKey := generateSecret(issuerPubKey) //secret=riG, lockKey=rG, issuerPubKey=iG

	scoring := erq.Scoring

	scoring.Score.Value, _ = encryptAES(scoring.Score.Value, secret)
	scoring.Score.Encrypted = true

	scoring.LockKey.Value, _ = encryptRSA(lockKey, clientPubKey)

	return nil, nil
}

func decodeIssuerKey(txt string) (*ed25519.PublicKey, error) {
	return nil, nil
}

func decodeClientKey(txt string) (*rsa.PublicKey, error) {
	return nil, nil
}

func encryptAES(plaintext string, secret []byte) (ciphertext string, err error) {
	return "dummyAESciph", nil
}

func generateSecret(pbk *ed25519.PublicKey) (secret []byte, lockKey []byte) {
	return nil, nil
}

func encryptRSA(plaintext []byte, rsa *rsa.PublicKey) (ciphertext string, err error) {
	return "dummyRSAciph", nil
}
