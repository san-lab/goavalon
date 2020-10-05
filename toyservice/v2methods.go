package toyservice

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"github.com/san-lab/goavalon/crypto"
	"io/ioutil"
	"math/big"
	"net/http"
)

func encryptCredentials(wr http.ResponseWriter, req *http.Request) {

	bbuf, err := ioutil.ReadAll(req.Body)
	if err != nil {
		fmt.Fprintln(wr, err)
		return

	}
	cred := new(CredentialWLockVer2)
	err = json.Unmarshal(bbuf, cred)
	if err != nil {
		fmt.Fprintln(wr, err)
		return
	}

	//Parse Customers Public Key
	rsapub, err := crypto.ParseRSAPublicKey(cred.SubjecSPublicKey)
	if err != nil {
		wr.WriteHeader(http.StatusBadRequest)
		fmt.Fprintln(wr, err)
		fmt.Println(err)
		return
	}

	hexkey := cred.IssuerPublicKey.IssuerPublicKey
	becpub, err := ParseEd25519PublicKey(hexkey)
	//fmt.Println(hex.EncodeToString(becpub[:]),err)

	//TODO Use seed as Ed usually does
	ephEd25519private := make([]byte, 32)
	rand.Reader.Read(ephEd25519private)
	ephEd25519private[0] &= 127 //This should work instead of actual MOD
	//fmt.Println(hex.EncodeToString(ephEd25519private[:]))

	t := new(big.Int)
	t.SetBytes(ephEd25519private)
	ephPrivInternal := Tli(t)
	ephEdpublic := EdwardsScalarMultB(ephPrivInternal)

	//fmt.Println(hex.EncodeToString(ephEdpublic[:]))

	//Shared secret
	Zero := Tli(big.NewInt(0))
	ss := EdwardsScalarAddMult(ephPrivInternal, becpub, Zero)

	plaintext := hex.EncodeToString(ephEdpublic[:])

	//Verification
	//x := new(big.Int)
	//x.SetString(BankEd, 10)
	//bankEdPriv := Tli(x)
	//ss2 := EdwardsScalarAddMult(bankEdPriv, ephEdpublic, Zero)
	//plaintext2 := hex.EncodeToString(ss2[:])
	//fmt.Println("a",plaintext)
	//fmt.Println("b", plaintext2)

	ciphertext, _ := EncryptWithRSAKey(plaintext, rsapub)
	b64ciphertext := base64.StdEncoding.EncodeToString(ciphertext)

	cred.Credential.LockKey.Encrypted = true
	cred.Credential.LockKey.Value = b64ciphertext

	//TODO: Handle different block types, do not assume len(ss)==32
	scorebytes, err := EncryptAESString(ss[:], cred.Credential.Score.Value)
	if err != nil {
		wr.WriteHeader(http.StatusBadRequest)
		fmt.Fprintln(wr, err)
		fmt.Println(err)
		return
	}
	score64base := base64.StdEncoding.EncodeToString(scorebytes)

	cred.Credential.Score.Encrypted = true
	cred.Credential.Score.Value = score64base

	ncred, err := json.MarshalIndent(&cred, "  ", "  ")
	if err != nil {
		wr.WriteHeader(http.StatusBadRequest)
		fmt.Fprintln(wr, err)
		fmt.Println(err)
		return
	}
	wr.Header().Set("Content-type", "application/json")
	wr.Header().Set("SymAlg", "AES-256-GCM")
	wr.Header().Add("SymKey", hex.EncodeToString(ss[:]))
	wr.Header().Add("Enclave-Ed25519-private", fmt.Sprintf("%x", t))
	wr.Header().Add("IV", hex.EncodeToString(scorebytes[0:12]))
	wr.Header().Add("ScoreBytes", hex.EncodeToString([]byte(cred.Credential.Score.Value)))
	wr.WriteHeader(http.StatusOK)
	wr.Write(ncred)
}

func issueCredentials(w http.ResponseWriter, r *http.Request) {
	bbuf, err := ioutil.ReadAll(r.Body)
	if err != nil {
		fmt.Fprintln(w, err)
		return

	}
	clreq := new(ClaimRequestType)
	err = json.Unmarshal(bbuf, clreq)
	if err != nil {
		fmt.Fprintln(w, err)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	//cred := CredentialWLock{}
	cred := CredentialWLockVer2{}
	cred.Credential.Name = clreq.Name
	cred.Credential.DID = clreq.DID
	//TODO validate the type
	cred.Credential.Type = clreq.Type

	cred.IssuerName = "DUMMY ISSUER - put your name here"
	//cred.IssuerPublicKey.IssuerPublicKeyX = "53d8775849f6eeea72adb402f64df032641ebc390e12c9fd364bbb521606e712"
	//cred.IssuerPublicKey.IssuerPublicKeyY = "03152df5be7401f44ac1039cead163203ad0da687c8988c2156535430358c06c"
	cred.IssuerPublicKey.IssuerPublicKey = "6cc0580343356515c288897c68dad03a2063d1ea9c03c14af40174bef52d1503"

	cred.Credential.Score.Encrypted = false
	cred.Credential.Score.Value = "A Plus"

	cred.SubjecSPublicKey = PubRSA

	SignByEd(&cred, BankEd)

	bytes, err := json.Marshal(&cred)
	if err != nil {
		fmt.Println(err)
		w.Write([]byte(fmt.Sprint(err)))
	}
	w.Header().Set("Content-type", "application/json")
	w.WriteHeader(http.StatusOK)
	w.Write(bytes)
	fmt.Println(string(bytes))

}

//Sign the 'Credential' json
//The private key is expected as a decimal string
//TODO externalize string gathering
func SignByEd(cred *CredentialWLockVer2, prvIssuer string) {
	test := cred.Credential.Name + cred.Credential.DID + cred.Credential.Type + cred.Credential.Score.Value + cred.IssuerDID

	x := new(big.Int)
	x.SetString(prvIssuer, 10)
	bankEdPriv := Tli(x)
	//Proper private key is 32 bytes privInt + 32 bytes public point
	mockpriv := make([]byte, 64)
	copy(mockpriv, bankEdPriv[:])
	cred.IssuerSignature = hex.EncodeToString(ed25519.Sign(mockpriv, []byte(test)))
}
