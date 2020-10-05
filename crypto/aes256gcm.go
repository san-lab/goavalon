package crypto

import (
	"fmt"
	"crypto/aes"
	"crypto/cipher"
)



//This is AES-256-GCM encryption
// [32] - symkey
// [12] - nonce/iv
// The label/extradata is set to nil
func EncryptAESBytes(skey []byte, nonce []byte, plaintext []byte) (ciphertext []byte, err error) {
	// AES encryption
	block, err := aes.NewCipher(skey)
	if err != nil {
		return nil, fmt.Errorf("cannot create new aes block: %w", err)
	}



	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("cannot create aes gcm: %w", err)
	}

	taglast := aesgcm.Seal(nil, nonce, plaintext, nil)
	//tagfirst := append(taglast[len(taglast)-16:], taglast[:16]...)
	return taglast, nil

}

//This is AES-256-GCM encryption
func DecryptAES(skey []byte, nonce []byte, ciphertext []byte) (plaintext []byte, err error) {
	if len(skey) != 32 {
		return nil, fmt.Errorf("wrong key length: %v", len(skey))
	}
	if len(nonce) != 12 {
		return nil, fmt.Errorf("wrong nonce/iv length: %v", len(skey))
	}


	block, err := aes.NewCipher(skey)
	if err != nil {
		return nil, fmt.Errorf("cannot create new aes block: %w", err)
	}
	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("cannot create new aes block: %w", err)
	}
	plaintext, err = aesgcm.Open(nil, nonce, ciphertext, nil)
	return
}