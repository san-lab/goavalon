package toyservice

import (
	"crypto/rsa"
	"fmt"
	"crypto/x509"
	"encoding/pem"
	"crypto/rand"
	"crypto/sha512"
	"golang.org/x/crypto/ed25519"
	"github.com/agl/ed25519/edwards25519"
)

var PubRSA = `-----BEGIN RSA PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAs+ZGv20suqeVy+LrA+tr
hYdov0IQvWLavVw5v383d8rRbnjXxB0UroX+61/9olL0KnYpgCKr+UC+1uf3FuFs
008DMkKSg8umWrV+8etHPZa31qSBgYWgrlygScAoPU5yQY3x/7NFFaIAs89bCw2J
5kKcQh/NHk+dRAYuQ4qmo6OKp0TW065MEprpfWZHgc9uynk7fRG+DHyLtGxkjb2J
6nSPSm7wK8Sb75YZV7orU1R80Brn1zbVxBKheLGfKgc7QK/6SuASlssR4pe58zIi
/KJtO8CqzpzmJShaxnPlxaUr7GRs3mCnMOL0bUYTkQsqUEfx/imh8PM7eXWuBAOF
LQIDAQAB
-----END RSA PUBLIC KEY-----`


var PrivRSA = `-----BEGIN RSA PRIVATE KEY-----
MIIEogIBAAKCAQEAs+ZGv20suqeVy+LrA+trhYdov0IQvWLavVw5v383d8rRbnjX
xB0UroX+61/9olL0KnYpgCKr+UC+1uf3FuFs008DMkKSg8umWrV+8etHPZa31qSB
gYWgrlygScAoPU5yQY3x/7NFFaIAs89bCw2J5kKcQh/NHk+dRAYuQ4qmo6OKp0TW
065MEprpfWZHgc9uynk7fRG+DHyLtGxkjb2J6nSPSm7wK8Sb75YZV7orU1R80Brn
1zbVxBKheLGfKgc7QK/6SuASlssR4pe58zIi/KJtO8CqzpzmJShaxnPlxaUr7GRs
3mCnMOL0bUYTkQsqUEfx/imh8PM7eXWuBAOFLQIDAQABAoIBAFu62m43c+xFEXuh
3CXmf6/ZiM6lGDYJVvHhOczsSFM7xqhm09Y64dXPm1lXW9POKpQQJj8g7sGsguK/
6tzu2vewPTf+fAjZ6ZwtGWqvhmbgGCNJRIPPqEvgDRct9Ra1jkrg3vl75okOTv9g
htLO93bCljydTJDdFZqe8C4eX7PmD+KB6mquyZZfLwclgyOu4VOwHvIRftAJSQ0w
fNskxIPeLO3zvbQQuv7/muNJb5EJAoQXW2RwN9IIJ4W/geVY5gYtCJWiEg52zO5e
Ahw7039T3TjPO604hJszfWQh7T9/CTvkQkjd19RTWCOgQbOFAmMlmOb5bWt0fjBh
CUv0w/0CgYEA4gOAIBgnUuvULdYXXqkUiYPtmwVW+sWL6UcnXaz3W3F2oEhlV03O
oGw8XGqTKvOzT1oGYC+tX/czctDsWlfvni5aP1NKeIMI9lpNjLsAgwdbSFltD9o0
Npe2Ad6fe/ANaxSFA0+/ctQ2lgiXOMHHATwP/lJHaNzBrCohruAFlcMCgYEAy8SF
DamRnqFtUD1FeCPMPVEDpqQNJ8JmdNtfr53zviVBILe8+gufl2tl+xQ8MTkB2jAZ
mvQYEjNfhNb70uvjO+jUEOKelx+qBtbf2WDPzncp3EMxjKf/uBycRSi01TJismVF
faKTzuTPwgeOP3tGmOjjrOGq3PtjgMsvjJbRmk8CgYAqVeWGHYAgNDSGcXfnL1y9
dYzoYNOuHZrbk4x4K5IZ+uLxmx4AgH6X5i5YUU5H2WZZEs/m7IdZVoC4nRHoylgE
FUKqYfutHz5qhvfHyK+L27DpmHapZYIqR7i8GOte19Rrnmhb+nAuHjorWGibJREV
1h5Y0Si3J8LPcQTmMOha6QKBgCGarzapmFJI3PY2pJZDkRMroSaCN4kvDiaHZyhX
LDNXgX4bzxaNhCw8kfzuQV78v8lz1UUwrCeUQVRu/+iw7jCbHR4LwYu6tRebqB75
UEwEaurgSfOgYRPD5CGjrO7b+FrjSKqHfUjJg1nEVTky41mkTqfcL4lyC97Zo2XU
GY0RAoGAWPDL0HdVcBA0kASACHL3x17OqW2zyycWVS2rERwg54KQ18SUxRbPG7Gk
1aERHpYZgUpiLmHPWTIDakKCGI+Jenk1B/O4/trqCT7gLaAZPyhuNcF6+lBn+MuQ
c8dROkdorq0/tUi5efqlNOkrEVXIhT1o/+dUb/O94HsROHFyrdw=
-----END RSA PRIVATE KEY-----`






func TestRSA() {
	pub, e := ParseRSAPublicKey(PubRSA)
	priv, e := parseRSAPrivKeyPEM(PrivRSA)
	fmt.Println("error:", e)
	fmt.Println(priv.PublicKey.N)
	fmt.Println(pub.N)
}

func parseRSAPrivKeyPEM(privPEM string)(*rsa.PrivateKey, error){
	block, _ := pem.Decode([]byte(privPEM))
	if block == nil {
		return nil, fmt.Errorf("Could not decode the key")
	}

	priv, err := x509.ParsePKCS1PrivateKey( block.Bytes)
	if err != nil {
		return nil, err
	}
	return priv, nil

}

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


func RsaKey() {
	privkey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		fmt.Println(err)
		return
	}
	prb := EncodePrivateKeyToPEM(privkey)
	fmt.Println(string(prb))

	pbb, err := EncodePubKeyToPEM(&privkey.PublicKey)
	if err != nil {
		fmt.Println(err)
		return
	}
	fmt.Println(string(pbb))
}


// EncodePrivateKeyToPEM encodes Private Key from RSA to PEM format
func EncodePrivateKeyToPEM(privateKey *rsa.PrivateKey) ([]byte) {
	// Get ASN.1 DER format
	privDER := x509.MarshalPKCS1PrivateKey(privateKey)

	// pem.Block
	privBlock := pem.Block{
		Type:    "RSA PRIVATE KEY",
		Headers: nil,
		Bytes:   privDER,
	}

	// Private key in PEM format
	privatePEM := pem.EncodeToMemory(&privBlock)

	return privatePEM
}

func EncodePubKeyToPEM(pubembedded *rsa.PublicKey) ([]byte, error) {
	PubASN1, err := x509.MarshalPKIXPublicKey(pubembedded)
	if err != nil {
		return nil, err
	}

	pubBytes := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PUBLIC KEY",
		Bytes: PubASN1,
	})
	return pubBytes, nil
}

//-----------------Ed25519--------------------

func Priv25519() {
	pub, prv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		fmt.Println(err)
		return
	}

	prv2 := ed25519.NewKeyFromSeed(prv.Seed())

	privBytes := pem.EncodeToMemory(&pem.Block{
		Type:  "Ed25519 PRIVATE KEY",
		Bytes: prv.Seed(),
	})
	fmt.Println(string(privBytes))

	privBytes = pem.EncodeToMemory(&pem.Block{
		Type:  "Ed25519 PRIVATE KEY",
		Bytes: prv2,
	})
	fmt.Println(string(privBytes))

	digest := sha512.Sum512(prv2.Seed())
	digest[0] &= 248
	digest[31] &= 127
	digest[31] |= 64

	var A edwards25519.ExtendedGroupElement
	var hBytes [32]byte
	copy(hBytes[:], digest[:])
	edwards25519.GeScalarMultBase(&A, &hBytes)
	var publicKeyBytes [32]byte
	A.ToBytes(&publicKeyBytes)
	pub2 := publicKeyBytes[:]
	//if err!= nil {
	//	fmt.Println(err)
	//	return
	//}
	fmt.Println(len(prv),prv)
	fmt.Println(len(pub2),pub2)

	pubBytes := pem.EncodeToMemory(&pem.Block{
		Type:  "Ed25519 PUBLIC KEY",
		Bytes: pub,
	})
	fmt.Println(string(pubBytes))

	pubBytes = pem.EncodeToMemory(&pem.Block{
		Type:  "Ed25519 PUBLIC KEY",
		Bytes: pub2,
	})
	fmt.Println(string(pubBytes))


	b2, _ := pem.Decode(pubBytes)
	fmt.Println(b2.Bytes)

	fmt.Println(prv[32:])


}



