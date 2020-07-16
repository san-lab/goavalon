package toyservice

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"github.com/agl/ed25519/edwards25519"
	"crypto/ed25519"
	"math/big"
	"net/http"
	"github.com/san-lab/goavalon/structs"
	"io/ioutil"
	"encoding/json"
	"crypto/sha256"
	"encoding/base64"
)

var ServPrivRSA = `-----BEGIN RSA PRIVATE KEY-----
MIIEpAIBAAKCAQEA2yqhreLQ+ZTobEffPysElNgOkiGnIBy+RfiCI98cvfE9cJ5a
f/aClE9+uuFTjTMOpZeRCRdOYZUYDFK7v+WbrS1c/XqLZr1bi2IRDp/HnhaZamMR
THDcxoBSVd1L/+uTvwgm1LWI2EmvHdMzwnOZpVlvUnBNV1nICAwAxTbHjmK8YPr8
QWsEx6Fql9Bn3ZqWm1hQj5u+xDFHSunFYYP6i2F4RomWYKpItQV0QBtI/6pib6PH
DH3VQLVAVetkhj7TPNOWak+QXe/79oOnarjXnz0224m2eHyutpPMZM3sl8Ocb061
C965So6eHEZqkxF1btfbEG9el3No7XUNHbYsvwIDAQABAoIBABSFEU4uhlJX1ssM
j6JibLNi5zpXXEZtaoMymTyyjwZZp977dI22jtND/iGRJzl5Jk3quvGW9Qe95dqB
hIKbBNBaBvLUnmioIgIS1HYCD7aFdye2zs/RYVpUeWEArzTu4Y5pPPl9Zaqae4LX
W2lBWYlZrkqRqSwcg9X9CbVtQ5HZEF8q1G+PfcCbwADP6q6DNWC3q8oGhEBTXK7S
OPhryJ/cImwHfI9LRabLbFcVKrf+/yqDX3Mgwrz7ykn8KZCP/0opUNZxVetCIxWT
Hi0CZQfp7a9WI3haj1WYMcbUU6UVIWEtDseFIvw4gTQojStzl01MaQTK3G5qu9vo
8B+DasECgYEA7deyQNjZjnjp6CTqoJx7KXpe8mccRDuhB5fo+kqV4koGMadBC3sb
SEiKL5EvnE2eonYH4FNIvVVyfgEX2tWQ22KGZH8qNToopctlDLPInsNEdbGeimo/
MrQ7Jxex0nDHlpiXqEBOutkid4lvmRcZ2TvPU9SEoLztAo/DAkVF0NUCgYEA6+Xw
Ihv4tWKuI3foTX6fw76iu+BO0gdpUqIGz1F5kO1h2yRgjJ3ONhL8o7PdP1aFnDLp
QOdCMwxdfasAyD3MWOOfLUGASu1fRSiGP+ymtUIl6dSl9wynTUZ0X+sPpkao+o+w
Cu9yLx3VupJuoJZNm36kzUZvh7raFKZBumN48UMCgYEA2TBs4HalREr6HjkH4J7E
gT3z0huCXnStOcfowha2BCxgt5rp9Nf4M+u59HH6LhtbTzPFQX4MIIkUwiexZu47
F3tDCiZtnql7UNsJba4G96OMsoT+J5uaFm0qzyn+AhNmzwiNBOGkg0+g/9OLCxtj
SVIqo3yfmECtlfc9tqcXd/kCgYBmwtrRsQet1FfxgXmD0KY+Ohxf5X3QhoP+CDEZ
PO/ND2uyb+1TNCcxbSH7Gg5GWiWH/rGXoWY4IKnVZZnIoQsUqcuchk0h1rfKw7V/
wVJ54V/stcK6lRuIUSm+4wIFOADCbbeNe/NszP1e8g0ZDYCvPQMDnSxWnzIDDs3R
KSX1SwKBgQCRiIhbG2wLU4lrsgOKeOT29loW1Pj5uURGczNM7BkH+vD6ED/JqpP8
GhUbyMO00vTiJlvPLOgkOKRT4DkgPwWRuwJfElrNw1kBdE7qlB9fiKhbTCaBDKtm
qke5UtJMpT0xmhPph8UeF/5UU21lzoJMBTDsNNztzUUiqMnQQCyn1Q==
-----END RSA PRIVATE KEY-----`

var ServPubRSA = `-----BEGIN RSA PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA2yqhreLQ+ZTobEffPysE
lNgOkiGnIBy+RfiCI98cvfE9cJ5af/aClE9+uuFTjTMOpZeRCRdOYZUYDFK7v+Wb
rS1c/XqLZr1bi2IRDp/HnhaZamMRTHDcxoBSVd1L/+uTvwgm1LWI2EmvHdMzwnOZ
pVlvUnBNV1nICAwAxTbHjmK8YPr8QWsEx6Fql9Bn3ZqWm1hQj5u+xDFHSunFYYP6
i2F4RomWYKpItQV0QBtI/6pib6PHDH3VQLVAVetkhj7TPNOWak+QXe/79oOnarjX
nz0224m2eHyutpPMZM3sl8Ocb061C965So6eHEZqkxF1btfbEG9el3No7XUNHbYs
vwIDAQAB
-----END RSA PUBLIC KEY-----`

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

var PrivEd25519 = `-----BEGIN Ed25519 PRIVATE KEY-----
VJB1ydQghGGMz5aiG/nLlrEaOwW1IxN2fWpzSOQ7jZ2h3aRws5TnTOAIxoM5r1uy
wRTpOhcsMMJ/3jvSLxOQ3w==
-----END Ed25519 PRIVATE KEY-----`

var PubEd25519 = `-----BEGIN Ed25519 PUBLIC KEY-----
od2kcLOU50zgCMaDOa9bssEU6ToXLDDCf9470i8TkN8=
-----END Ed25519 PUBLIC KEY-----`

func TestRSA() {
	pub, e := ParseRSAPublicKey(PubRSA)
	priv, e := parseRSAPrivKeyPEM(PrivRSA)
	fmt.Println("error:", e)
	fmt.Println(priv.PublicKey.N)
	fmt.Println(pub.N)
}

func parseRSAPrivKeyPEM(privPEM string) (*rsa.PrivateKey, error) {
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
func EncodePrivateKeyToPEM(privateKey *rsa.PrivateKey) []byte {
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

func ParseEd25519Priv(pemtext string) (ed25519.PrivateKey, error) {
	block, _ := pem.Decode([]byte(pemtext))
	if len(block.Bytes) != 64 {
		return nil, fmt.Errorf("Wrong byte count")
	}
	seed := block.Bytes[:32]
	priv := ed25519.NewKeyFromSeed(seed)
	x := priv.Public().(ed25519.PublicKey)
	if !bytes.Equal(x, block.Bytes[32:]) {
		return nil, fmt.Errorf("Validation mismatch")
	}
	return priv, nil
}

func ParseEd25519PubPEM(pemtext string) (ed25519.PublicKey, error) {
	block, _ := pem.Decode([]byte(pemtext))
	if len(block.Bytes) != 32 {
		return nil, fmt.Errorf("Wrong byte count")
	}
	return ed25519.PublicKey(block.Bytes), nil
}

func EncodeEd25519Priv(prv ed25519.PrivateKey) string {
	privBytes := pem.EncodeToMemory(&pem.Block{
		Type:  "Ed25519 PRIVATE KEY",
		Bytes: prv,
	})
	return string(privBytes)
}

func EncodeEd25519Pub(pub ed25519.PublicKey) string {
	pubBytes := pem.EncodeToMemory(&pem.Block{
		Type:  "Ed25519 PUBLIC KEY",
		Bytes: pub,
	})
	return string(pubBytes)
}

func TestPriv25519() {

	prv, _ := ParseEd25519Priv(PrivEd25519)

	pub, _ := ParseEd25519PubPEM(PubEd25519)

	privpem := EncodeEd25519Priv(prv)
	fmt.Println(privpem)

	prv2, _ := ParseEd25519Priv(privpem)

	fmt.Println(pub)
	fmt.Println(prv2.Public())

	//edwards25519.GeScalarMultBase(&A, &hBytes)
	//var publicKeyBytes [32]byte
	//A.ToBytes(&publicKeyBytes)

}

var BankPrivateKeyString = "8922796882388619604127911146068705796569681654940873967836428543013949233636"
func D() {
	x := new(big.Int)
	x.SetString(BankPrivateKeyString, 10)
	fmt.Println(x)
	fmt.Println(x.Bytes())

	hBytes := new([32]byte)

	//copy(hBytes[:], x.Bytes()[:32])
	for i := len(x.Bytes()); i > 0; i-- {
		hBytes[32-i] = x.Bytes()[i-1]
	}
	fmt.Println(hBytes)
	A := new(edwards25519.ExtendedGroupElement)
	edwards25519.GeScalarMultBase(A, hBytes)

	var publicKeyBytes [32]byte
	A.ToBytes(&publicKeyBytes)

	fmt.Println(publicKeyBytes[31] & 128)

	fmt.Println(hex.EncodeToString(publicKeyBytes[:]))
	fmt.Println(hex.EncodeToString(Reverse(publicKeyBytes)[:]))

}



func G() {
	pu,pr,er:= ed25519.GenerateKey(rand.Reader)
	fmt.Println(pu,pr,er)
}

//s[31] ^= FeIsNegative(&x) << 7
//
//

var newJson = `{
    "jsonrpc": "2.0",
    "method": "WorkOrderSubmit",
    "id": 11,
    "params": {
        "responseTimeoutMSecs": 6000,
        "payloadFormat": "JSON-RPC",
        "resultUri": "resulturi",
        "notifyUri": "notifyuri",
        "workOrderId": "0x8ce9ec0df71ca821",
        "workerId": "0b03616a46ea9cf574f3f8eedc93a62c691a60dbd3783427c0243bacfe5bba94",
        "workloadId": "dalion-encrypt",
        "requesterId": "0x1111",
        "dataEncryptionAlgorithm": "AES-GCM-256",
        "encryptedSessionKey": "957df67fb332445d26a5e0484c0ff229d4614d3c076537dd74ee366c1df2ccd8510483e86422f80c906a06ee8686b0a4d222a2da31c833e23e4d667716c997e66fab2fb4ff9740db68c9327f978b6ecd60b5b1120ddf86f8fc10d0484bf8185a612b539e66d669c63c7459d188df37616374db53b8d7a746b55c0bb400f9c3cb03c8b2881af895e8c92b1c1fd9f536b6eaa0101637fc088c2215e667c6cf4f50657b46f7b6a0811f080df81153d4bdb6f6057d260f3ae6d7069efeacc713e15ad1e09c5c8e7e29e2cbdd2585315bc24d7e41cef72c62b18ef89b51041fb6450f2e6b937cbc8146ea7d23bbc0e087bd4a5aafbc147c72e8ce7d307ae332fedf3aa4398656ea71437ce80a54a08c7620c31aa7e5fe91ff90c54aba04fd8c7c0039cd9e71a077cb4e65c48bbd2e160117a489fd7ff60048d2c98f40019ef8cd19fc8ba9936f58f9ea16e97032878461eef944d261d13eb203833620742bbd90ea887bd3ede46421b52f84ad41685f5c4be75edbbc81d2fe0b7a10114e102a154431",
        "sessionKeyIv": "00000000000000000000000000000002",
        "requesterNonce": "",
        "encryptedRequestHash": "requesthash",
        "requesterSignature": "",
        "inData": [
            {
                "index": 0,
                "data": "9e22c09339c0435a0f848af6c29944e2a7a72d4b201439b3244c702eba598b83f604614d494d27454e8dfbec3e635180ad8451d8a001c8b9fe273ed5d9f87cb6e113ee7eb62e2dba929924b8962d2b8c81be67839afc3a67ccc9aaa4c50b1330ca1d74ea4b5b47fb34b86e1d9cbe67f7739ad882d06535bf94fa6a16bef01b20dd4b0dfd33ec5b1079cb88ee88201f1dc98992383cc6e2024575e50475ee980c326ccc501a7a2ad82dbca1ce895449cff4c20a015587019800e0ddea866e2554196c28310d0481302e5ef514815e60a6f0a22c5ae966a3b9bb541eba515bba106482183d7c48340a3d1c0c424b441f31040bb726a6604ef1c74287e749e967d139a2889f320847ae4cfc882448ab75aad6025bf0fd638178188788b73f265a391d5a78777be3a1bdb5e83b5f5325d976d07425c6776f38d110d591e69d11a0a32a9d0ac4a40daae5a40f02a03a67c24d82a428a38c3610797155c10df97120fdad86f7dbd8e01fc219f8f3e2ef86a96a6a8363f552388e0af6f18504f3e557ae184ce608ad1cb8e837566a14de05cccbd8dd000511b4ae4d0ed92246164986ea91dac18d7cf1d66804f4be0bfce54e081293e53a9941fcfb599d1bcb1f2b091fe51823d2f1dcce867673e9f3159b280cf182d9c3aeee6b446881923b6b616f8c2f46a50d1487909eeb8e58c3fa2f0d204254de36405a0b071a95e0ee6e10ebbdb922f6b05d55e887ea4e5a605b4b2ec88825220d733ab5711cde050865690b09867516f0edf9c4aa7dea3cb17858d78fcc619bfe7420fe685f9ff094896e843b401777597911fc23abe7b717e552a5e2d30f6a359a497b74eab2c9ad3ad470ebe99376c9dfa5631f2490b66ed4573e52ad023b7d100fd5010dd49f8d0cba29233310172f45be45f8ba71daa6d7cf27cb0a219ec5ea944969d261c9eaa3846c795762bdae21024dbbc0e24b36657969aa850cd20975ed7099114b5f3184b63af46334bb4d48a67ab3b13358deaee357490f1c704dc37207debfa21b94f472951d8ffbe5d67ac904d8cf89bdf212858e7f23f4207bc1a13f9509ea375ab829005eabce652b7a72a03888146ec60c6603cfcc05e8b6569e92a1a1a1fa84d7357cf5d536a63aaed34e9e5d155a23abd981a2e485143eeb3be02b5e651bd7cbcf14d148cf661740ed71ec82a990b415d7029112ff0ed3d0c84a1c28fe24ec8350d3396759e1a880bad658f17734f1944a323079326fd664e9635bcac5ef788b0b35fd1f49861ff04679aad3c0ae8a83fd6518ff9f42c72c7daedec307b383b84adce401189d6ff10ce622619d5168469b396e09217b4ac26e3e25cd75f48f531cbb0525696dd338395fed"
            }
        ]
    }
}`

func woSubmit(wr http.ResponseWriter, req *http.Request) {
	rqj := new (structs.WorkOrderSubmit)
	bbuf, err := ioutil.ReadAll(req.Body)
	if err != nil {
		fmt.Fprintln(wr, err)
		return

	}
	err = json.Unmarshal(bbuf, rqj)
	if err != nil {
		fmt.Fprintln(wr, err)
		return

	}

	privrsa , err := parseRSAPrivKeyPEM(ServPrivRSA)
	if err != nil {
		fmt.Fprintln(wr, err)
		return

	}
	if err != nil {
		fmt.Fprintln(wr, err)
		return

	}
	encskey, err := base64.StdEncoding.DecodeString(rqj.Params.EncryptedSessionKey)

	sessionkey, err := rsa.DecryptOAEP(sha256.New(), rand.Reader, privrsa, encskey, nil)
	if err != nil {
		fmt.Fprintln(wr, err)
		return

	}
	fmt.Fprintln(wr, sessionkey)
	iv, err := hex.DecodeString(rqj.Params.SessionKeyIv)
	if err != nil {
		fmt.Fprintln(wr, err)
		return

	}
	ctdata, err := base64.StdEncoding.DecodeString(rqj.Params.InData[0].Data)
	if err != nil {
		fmt.Fprintln(wr, err)
		return

	}
	ctdata = append(iv,ctdata...)

	ptdata, err := DecryptAES(sessionkey, ctdata)
	if err != nil {
		fmt.Fprintln(wr, err)
		return

	}

	wosres := new (structs.WorkOrderSubmitResponse)
	wosres.Result.OutData = []structs.OutData{structs.OutData{}}
	wosres.Result.OutData[0].Data = string(ptdata)
	
	b, _ := json.MarshalIndent(wosres, "  ", "  ")
	wr.Write(b)

}

func workerDetails (wr http.ResponseWriter, req *http.Request) {
	wrr := new (structs.WorkerRetrieveRequest)
	bbuf, err := ioutil.ReadAll(req.Body)
	if err != nil {
		fmt.Fprintln(wr, err)
		return

	}
	err = json.Unmarshal(bbuf, wrr)
	if err != nil {
		fmt.Fprintln(wr, err)
		return

	}
	id := wrr.Params.WorkerID

	if id != "0042" {
		fmt.Fprintf(wr,"{\"Error\",\"No such worker: %s\"}", id)
		return
	}
	wdres := new(structs.WorkerRetrieveResponse)
	wdres.Result.Details.WorkerTypeData.EncryptionKey=ServPubRSA


	b,_ := json.MarshalIndent(wdres,"  ","  ")
	wr.Write(b)

}