package toyservice

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"github.com/agl/ed25519/edwards25519"
	"math/big"
	"strings"
	"github.com/btcsuite/btcd/btcec"
	"encoding/pem"

	"crypto/ecdsa"
	"encoding/asn1"
	"crypto/elliptic"
)

const RSA_ENCR_LABEL = "Encrypted with Public RSA key"

const RSAUserKey = `-----BEGIN RSA PRIVATE KEY-----
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

const EncRSAPriv = `-----BEGIN RSA PRIVATE KEY-----
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

const EncRSAPub = `-----BEGIN RSA PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA2yqhreLQ+ZTobEffPysE
lNgOkiGnIBy+RfiCI98cvfE9cJ5af/aClE9+uuFTjTMOpZeRCRdOYZUYDFK7v+Wb
rS1c/XqLZr1bi2IRDp/HnhaZamMRTHDcxoBSVd1L/+uTvwgm1LWI2EmvHdMzwnOZ
pVlvUnBNV1nICAwAxTbHjmK8YPr8QWsEx6Fql9Bn3ZqWm1hQj5u+xDFHSunFYYP6
i2F4RomWYKpItQV0QBtI/6pib6PHDH3VQLVAVetkhj7TPNOWak+QXe/79oOnarjX
nz0224m2eHyutpPMZM3sl8Ocb061C965So6eHEZqkxF1btfbEG9el3No7XUNHbYs
vwIDAQAB
-----END RSA PUBLIC KEY-----`

func EdwardsScalarAddMult(a, pointbytes, b *[32]byte) *[32]byte {
	r := edwards25519.ProjectiveGroupElement{}
	A := edwards25519.ExtendedGroupElement{}
	if ok := A.FromBytes(pointbytes); !ok {
		fmt.Println("failed .FromBytes:", *pointbytes)
		return nil
	}
	// GeDoubleScalarMultVartime sets r = a*A + b*B
	edwards25519.GeDoubleScalarMultVartime(&r, a, &A, b)
	fb := new([32]byte)
	r.ToBytes(fb)
	return fb
}

func EdwardsScalarMultB(scalar *[32]byte) *[32]byte {
	A := new(edwards25519.ExtendedGroupElement)
	x := new([32]byte)
	edwards25519.GeScalarMultBase(A, scalar)
	A.ToBytes(x)
	return x
}

const EdBaseBytesString = "5866666666666666666666666666666666666666666666666666666666666666"
const BankEd = "8922796882388619604127911146068705796569681654940873967836428543013949233636"
const Ed25519OrderString = "7237005577332262213973186563042994240857116359379907606001950938285454250989"
const Ed25519PrimeString = "57896044618658097711785492504343953926634992332820282019728792003956564819949"

var EdBase *[32]byte //little endian!
var EdOrder, EdPrime big.Int

func initEd() {
	//EdOrder = new(big.Int)
	//EdPrime = new(big.Int)
	EdOrder.SetString(Ed25519OrderString, 10)
	EdPrime.SetString(Ed25519PrimeString, 10)
	EdBase, _ = PfromString(EdBaseBytesString)
}

func TestEd() {
	pb := "AAAAC3NzaC1lZDI1NTE5AAAAIJyeWuLLq4lAJaRguhULIJksZU/OhQZ8074o+aq2wZXp"
	pr := `b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW
QyNTUxOQAAACCcnlriy6uJQCWkYLoVCyCZLGVPzoUGfNO+KPmqtsGV6QAAAKDKRj5jykY+
YwAAAAtzc2gtZWQyNTUxOQAAACCcnlriy6uJQCWkYLoVCyCZLGVPzoUGfNO+KPmqtsGV6Q
AAAEBnofdRYHQps0A6MwsNpNPgE7GjkPgNf8mLe5YTkxvJkpyeWuLLq4lAJaRguhULIJks
ZU/OhQZ8074o+aq2wZXpAAAAG3NhbmxhYkBzYW5sYWItUE9SVEVHRS1aMzAtQgEC`

	b, _ := base64.StdEncoding.DecodeString(pb)
	fmt.Println(len(b), hex.EncodeToString(b))
	br, _ := base64.StdEncoding.DecodeString(pr)
	fmt.Println(len(br), hex.EncodeToString(br))

	pb1 := b[19:51]
	fmt.Println(len(pb1))
	fmt.Println(hex.EncodeToString(pb1))

	fmt.Println(hex.EncodeToString(br[62:94]))
	fmt.Println(strings.Index(hex.EncodeToString(br), "00000040"))
	fmt.Println(hex.EncodeToString(br[161:193]))

	i := new([32]byte)
	copy(i[:], br[161:193])
	fmt.Println(hex.EncodeToString(i[:]))
	fmt.Println(len(i))

	prk2 := ed25519.NewKeyFromSeed(i[:])
	fmt.Println(hex.EncodeToString(prk2))
}

func TestEdX() {
	initEd()

	var k1, k2, k3 [64]byte
	rand.Reader.Read(k1[:])
	rand.Reader.Read(k2[:])
	rand.Reader.Read(k3[:])

	ks1 := new([32]byte)
	ks2 := new([32]byte)
	ks3 := new([32]byte)
	edwards25519.ScReduce(ks1, &k1)
	edwards25519.ScReduce(ks2, &k2)
	edwards25519.ScReduce(ks3, &k3)

	//ks3 = Tli(big.NewInt(0))

	lix := new([32]byte)

	edwards25519.ScMulAdd(lix, ks1, ks2, ks3)
	A := EdwardsScalarMultB(ks1)
	B := EdwardsScalarMultB(ks2)
	Y1 := EdwardsScalarAddMult(ks1, B, ks3)
	Y2 := EdwardsScalarAddMult(ks2, A, ks3)
	logPoint("k1*(k2*B)+k3*B", Y1)
	logPoint("k2*(k1*B)+k3*B", Y2)
	Y3 := EdwardsScalarMultB(lix)
	logPoint("(k1*k2+k3)*B  ", Y3)

	ks1 = Tli(big.NewInt(0))
	ks3 = Tli(big.NewInt(1))
	edwards25519.ScMulAdd(lix, ks1, ks2, ks3)
	A = EdwardsScalarMultB(ks1)
	B = EdwardsScalarMultB(ks2)
	Y1 = EdwardsScalarAddMult(ks1, B, ks3)
	Y2 = EdwardsScalarAddMult(ks2, A, ks3)
	logPoint("k1*(k2*B)+k3*B", Y1)
	logPoint("k2*(k1*B)+k3*B", Y2)
	Y3 = EdwardsScalarMultB(lix)
	logPoint("(k1*k2+k3)*B  ", Y3)
}

//Recover big.Int from little-endian *[32]byte
func Fli(s *[32]byte) *big.Int {
	sr := Reverse(*s)
	i := new(big.Int)
	i.SetBytes(sr[:])
	return i
}

//To little-endian
func Tli(i *big.Int) *[32]byte {
	slice := i.Bytes()
	l := len(slice)
	if l > 32 {
		j := new(big.Int)
		j.Mod(i, &EdOrder)
		slice = j.Bytes()
		l = len(slice)
	}
	h1 := new([32]byte)

	for i, v := range slice {
		h1[l-i-1] = v
	}
	return h1
}

//Parse hex code into a [32]byte array pointer
func PfromString(h string) (*[32]byte, error) {
	bb, err := hex.DecodeString(h)
	if err != nil {
		return nil, err
	}
	B := new([32]byte)
	copy(B[:], bb)
	return B, nil
}

func logPoint(msg string, pt *[32]byte) {
	fmt.Println(msg, hex.EncodeToString(pt[:]))
}

func Reverse(edBytes [32]byte) *[32]byte {
	rev := new([32]byte)
	for i, v := range edBytes {
		rev[31-i] = v
	}
	return rev

}

//TODO Bring that in-line with the standards
func ParseEd25519PublicKey(pk string) (*[32]byte, error) {

	pkb, err := PfromString(pk)
	if err != nil {
		return nil, err
	}

	A := new(edwards25519.ExtendedGroupElement)
	if ok := A.FromBytes(pkb); !ok {
		return nil, fmt.Errorf("Invalid value for Ed25519 point")
	}
	return pkb, nil
}

func EncryptWithRSAKey(plaintext string, key *rsa.PublicKey) ([]byte, error) {

	b, e := rsa.EncryptOAEP(sha256.New(), rand.Reader, key, []byte(plaintext), []byte(RSA_ENCR_LABEL))
	if e != nil {
		return nil, e
	}
	return b, nil
}

//This is AES-256-GCM encryption
//The returned slice contains
//The first 12 bytes of the ciphertext are expected to carry the nonce
func DecryptAES(skey []byte, ciphertext []byte) (plaintext []byte, err error) {
	if len(skey) != 32 {
		return nil, fmt.Errorf("wrong key length: %v", len(skey))
	}
	nonce := ciphertext[:12]
	ciphertext = ciphertext[12:]
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

//This is AES-256-GCM encryption
//The returned slice contains
// [:12] - nonce/iv
// [12:] - ciphertext
// The label/extradata is set to nil
func EncryptAESString(skey []byte, plaintext string) (ciphertext []byte, err error) {
	// AES encryption
	nonce := make([]byte, 12)
	if _, err := rand.Read(nonce); err != nil {
		return nil, fmt.Errorf("cannot read random bytes for nonce: %w", err)
	}
	return EncryptAESBytes(skey, nonce, []byte(plaintext))
}

//This is AES-256-GCM encryption
// [32] - symkey
// [12] - nonce/iv
// The label/extradata is set to nil
//The returned slice contains
// [:12] - nonce/iv
// [12:] - ciphertext
func EncryptAESBytes(skey []byte, nonce []byte, plaintext []byte) (ciphertext []byte, err error) {
	// AES encryption
	block, err := aes.NewCipher(skey)
	if err != nil {
		return nil, fmt.Errorf("cannot create new aes block: %w", err)
	}

	var ct bytes.Buffer
	ct.Write(nonce)

	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("cannot create aes gcm: %w", err)
	}

	ct.Write(aesgcm.Seal(nil, nonce, plaintext, nil))
	return ct.Bytes(), nil
}



func SignByEd3(cred *CredentialWLockVer3, prvIssuer string) {
	test := collectSignString(cred)

	x := new(big.Int)
	x.SetString(prvIssuer, 10)
	bankEdPriv := Tli(x)

	cred.IssuerSignature = hex.EncodeToString(sSign(bankEdPriv, []byte(test)))
}

func collectSignString(cred *CredentialWLockVer3) string {
	return cred.Credential.Name + cred.Credential.DID + cred.Credential.Type + cred.Credential.Value + cred.IssuerDID
}

//TODO This is a hack because I cannot do any better parsing asn1 :-(
func ParseKoblitzPrivPem(pemstring string) (*btcec.PrivateKey, error) {
	blk, _ := pem.Decode([]byte(pemstring))
	if blk == nil {
		return nil, fmt.Errorf("Null Block")
	}
	if len(blk.Bytes) < len(ecPubKeyPreamble) {
		return nil, fmt.Errorf("Block too short")
	}
	keybytes := blk.Bytes[7:39]
	pk, _ :=  btcec.PrivKeyFromBytes(btcec.S256(),keybytes)
	return pk, nil
}
var ecPubKeyPreamble = []byte{48, 86, 48, 16, 6, 7, 42, 134, 72, 206, 61, 2, 1, 6, 5, 43, 129, 4, 0, 10, 3, 66, 0}

// Now I need to hijack this code from x509 because they do not know the Koblitz OID :-(
func MarshalECPrivateKey(key *ecdsa.PrivateKey) ([]byte, error) {
	//oid, ok := oidFromNamedCurve(key.Curve)
	//if !ok {
	//	return nil, errors.New("x509: unknown elliptic curve")
	//}
	oid := asn1.ObjectIdentifier{1,3,132,0,10}
	privateKeyBytes := key.D.Bytes()
	paddedPrivateKey := make([]byte, (key.Curve.Params().N.BitLen()+7)/8)
	copy(paddedPrivateKey[len(paddedPrivateKey)-len(privateKeyBytes):], privateKeyBytes)

	return asn1.Marshal(ecPrivateKey{
		Version:       1,
		PrivateKey:    paddedPrivateKey,
		NamedCurveOID: oid,
		PublicKey:     asn1.BitString{Bytes: elliptic.Marshal(key.Curve, key.X, key.Y)},
	})
}
type ecPrivateKey struct {
	Version       int
	PrivateKey    []byte
	NamedCurveOID asn1.ObjectIdentifier `asn1:"optional,explicit,tag:0"`
	PublicKey     asn1.BitString        `asn1:"optional,explicit,tag:1"`
}

func EcPubKeyBytesToPem(rawkey []byte) string {
	meatBytes := append(ecPubKeyPreamble, rawkey...)
	encMeatBytes := make([]byte, base64.StdEncoding.EncodedLen(len(meatBytes)))
	base64.StdEncoding.Encode(encMeatBytes, meatBytes)
	out := append(ecpbkHeader, insertNewLineEvery64(encMeatBytes)...)
	out = append(out, ecpbkFooter...)
	return string(out)
}

var ecpbkHeader = []byte("-----BEGIN PUBLIC KEY-----\n")
var ecpbkFooter = []byte("\n-----END PUBLIC KEY-----")

func insertNewLineEvery64(in []byte) (out []byte) {
	i := 64
	for ; i < len(in); i = i + 64 {
		out = append(out, in[i-64:i]...)
		out = append(out, '\n')
	}
	out = append(out, in[i-64:]...)
	return
}

func ParseKoblitzPubPem(pemstring string ) (*btcec.PublicKey, error){
	blk, r := pem.Decode([]byte(pemstring))
	fmt.Println(r)
	if blk == nil {
		return nil, fmt.Errorf("Null Block")
	}
	if len(blk.Bytes) < len(ecPubKeyPreamble) {
		return nil, fmt.Errorf("Block too short")
	}
	return btcec.ParsePubKey(blk.Bytes[len(ecPubKeyPreamble):], btcec.S256())

}