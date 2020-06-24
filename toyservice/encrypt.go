package toyservice

import "crypto"

func EncryptScoring (erq *EncryptRequest) (*Scoring, error){
	var issuerPubKey crypto.PublicKey
	var clientPubKey crypto.PublicKey
	issuerPubKey, _ = decodeIssuerKey(erq.Issuerpubkey)
	issuerPubKey, _ = decodeIssuerKey(erq.Issuerpubkey)

	secret, lockKey := generateSecret(issuerPubKey) //secret=riG, lockKey=rG, issuerPubKey=iG

	scoring := erq.Scoring

	return nil, nil
}

func decodeIssuerKey(txt string) (*crypto.PublicKey, error) {
	return nil, nil
}

func decodeClientKey(txt string) (*crypto.PublicKey, error) {
	return nil, nil
}

