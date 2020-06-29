package toyservice

import (
	"math/big"
	"github.com/agl/ed25519/edwards25519"
	"fmt"
	"encoding/hex"
	"crypto/rand"
	"encoding/base64"
	"strings"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/aes"
	"bytes"
	"crypto/cipher"
)

const RSA_ENCR_LABEL = "Encrypted with Public RSA key"

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

func EdwardsScalarAddMult(a , pointbytes , b *[32]byte ) *[32]byte {
	r := edwards25519.ProjectiveGroupElement{}
	A := edwards25519.ExtendedGroupElement{}
	if ok := A.FromBytes(pointbytes); !ok {
		fmt.Println("failed .FromBytes:", *pointbytes)
		return nil
	}
	// GeDoubleScalarMultVartime sets r = a*A + b*B
	edwards25519.GeDoubleScalarMultVartime(&r, a, &A, b )
	fb := new([32]byte)
	r.ToBytes(fb)
	return fb
}

func EdwardsScalarMultB(scalar *[32]byte) *[32]byte {
	A := new (edwards25519.ExtendedGroupElement)
	x := new([32]byte)
	edwards25519.GeScalarMultBase(A, scalar)
	A.ToBytes(x)
	return x
}




const EdBaseBytesString = "5866666666666666666666666666666666666666666666666666666666666666"
const BankEd  = "8922796882388619604127911146068705796569681654940873967836428543013949233636"
const Ed25519OrderString = "7237005577332262213973186563042994240857116359379907606001950938285454250989"
const Ed25519PrimeString = "57896044618658097711785492504343953926634992332820282019728792003956564819949"

var EdBase *[32]byte //little endian!
var EdOrder, EdPrime big.Int
func initEd() {
	//EdOrder = new(big.Int)
	//EdPrime = new(big.Int)
	EdOrder.SetString(Ed25519OrderString, 10)
	EdPrime.SetString(Ed25519PrimeString, 10)
	EdBase,_ = PfromString(EdBaseBytesString)
}

func TestEd() {
	pb := "AAAAC3NzaC1lZDI1NTE5AAAAIJyeWuLLq4lAJaRguhULIJksZU/OhQZ8074o+aq2wZXp"
	pr :=`b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW
QyNTUxOQAAACCcnlriy6uJQCWkYLoVCyCZLGVPzoUGfNO+KPmqtsGV6QAAAKDKRj5jykY+
YwAAAAtzc2gtZWQyNTUxOQAAACCcnlriy6uJQCWkYLoVCyCZLGVPzoUGfNO+KPmqtsGV6Q
AAAEBnofdRYHQps0A6MwsNpNPgE7GjkPgNf8mLe5YTkxvJkpyeWuLLq4lAJaRguhULIJks
ZU/OhQZ8074o+aq2wZXpAAAAG3NhbmxhYkBzYW5sYWItUE9SVEVHRS1aMzAtQgEC`

	b,_ := base64.StdEncoding.DecodeString(pb)
	fmt.Println(len(b), hex.EncodeToString(b))
	br,_ := base64.StdEncoding.DecodeString(pr)
	fmt.Println(len(br), hex.EncodeToString(br))

	pb1 := b[19:51]
	fmt.Println(len(pb1))
	fmt.Println(hex.EncodeToString(pb1))

	fmt.Println(hex.EncodeToString(br[62:94]))
	fmt.Println(strings.Index(hex.EncodeToString(br),"00000040"))
	fmt.Println(hex.EncodeToString(br[161:193]))

	i := new([32]byte)
	copy(i[:],br[161:193] )
	fmt.Println(hex.EncodeToString(i[:]))
	fmt.Println(len(i))

	prk2 := ed25519.NewKeyFromSeed(i[:])
	fmt.Println(hex.EncodeToString(prk2))
}

func TestEdX() {
	initEd()

	var k1,k2, k3 [64]byte
	rand.Reader.Read(k1[:])
	rand.Reader.Read(k2[:])
	rand.Reader.Read(k3[:])

	ks1 := new([32]byte)
	ks2 := new([32]byte)
	ks3 := new([32]byte)
	edwards25519.ScReduce(ks1,&k1)
	edwards25519.ScReduce(ks2,&k2)
	edwards25519.ScReduce(ks3,&k3)

	//ks3 = Tli(big.NewInt(0))


	lix := new([32]byte)
	
	edwards25519.ScMulAdd(lix, ks1, ks2, ks3)
	A := EdwardsScalarMultB(ks1)
	B := EdwardsScalarMultB(ks2)
	Y1 := EdwardsScalarAddMult(ks1,B, ks3)
	Y2 := EdwardsScalarAddMult(ks2,A, ks3)
	logPoint("k1*(k2*B)+k3*B", Y1)
	logPoint("k2*(k1*B)+k3*B", Y2)
	Y3 := EdwardsScalarMultB(lix)
	logPoint("(k1*k2+k3)*B  ", Y3)

	ks1 = Tli(big.NewInt(0))
	ks3 = Tli(big.NewInt(1))
	edwards25519.ScMulAdd(lix, ks1, ks2, ks3)
	A = EdwardsScalarMultB(ks1)
	B = EdwardsScalarMultB(ks2)
	Y1 = EdwardsScalarAddMult(ks1,B, ks3)
	Y2 = EdwardsScalarAddMult(ks2,A, ks3)
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
		l=len(slice)
	}
	h1 := new([32]byte)

	for i,v := range slice {
			h1[l-i-1] = v
		}
	return h1
}


//Parse hex code into a [32]byte array pointer
func PfromString(h string) (*[32]byte, error) {
	bb, err := hex.DecodeString(h)
	if err != nil {
		return nil,err
	}
	B := new ([32]byte)
	copy(B[:],bb)
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
func ParseEd25519PublicKey(pk IssuerPubKeyType) (*[32]byte,  error) {
	hexkey := pk.IssuerPublicKey
	pkb, err := PfromString(hexkey)
	if err != nil {
		return nil, err
	}

	A := new (edwards25519.ExtendedGroupElement)
	if ok:= A.FromBytes(pkb); !ok {
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
// [:12] - nonce/iv
// [12:] - ciphertext
// The label/extradata is set to nil
func EncryptAES(skey []byte, plaintext string ) ( ciphertext []byte, err error ){
	// AES encryption
	block, err := aes.NewCipher(skey)
	if err != nil {
		//return nil, fmt.Errorf("cannot create new aes block: %w", err)
	}

	nonce := make([]byte, 12)
	if _, err := rand.Read(nonce); err != nil {
		return nil, fmt.Errorf("cannot read random bytes for nonce: %w", err)
	}
	var ct bytes.Buffer
	ct.Write(nonce)

	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("cannot create aes gcm: %w", err)
	}

	ct.Write( aesgcm.Seal(nil, nonce, []byte(plaintext), nil))
	return ct.Bytes(),nil
}