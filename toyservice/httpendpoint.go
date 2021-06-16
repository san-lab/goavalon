package toyservice

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"

	//"github.com/clearmatics/bn256"
	"io/ioutil"
	"log"
	"math/big"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"sync"

	"github.com/san-lab/goavalon/crypto"
)

func StartServer() {
	httpPort := flag.String("httpPort", "8080", "http port")
	httpsPort := flag.Int("httpsPort", 0, "https port. tls not started if not provided. requires server.crt & server.key")
	goAvalonPath := flag.String("goavalon path", "goavalon", "path to the goavalon service endpoint")
	flag.Parse()

	interruptChan := make(chan os.Signal)
	wg := &sync.WaitGroup{}
	ctx := context.Background()
	ctx, cancel := context.WithCancel(ctx)
	ctx = context.WithValue(ctx, "WaitGroup", wg)
	ctx = context.WithValue(ctx, GoAvalonPath, *goAvalonPath)
	fs := http.FileServer(http.Dir("static"))
	http.HandleFunc("/static/", http.StripPrefix("/static", fs).ServeHTTP)
	signal.Notify(interruptChan, os.Interrupt)
	gav := NewService(ctx)
	http.HandleFunc("/"+*goAvalonPath, gav.TheHandler)
	http.HandleFunc("/", TheRestHandler)

	srv := http.Server{Addr: ":" + *httpPort}
	var tlsSrv http.Server
	if *httpsPort > 0 {
		tlsSrv = http.Server{Addr: ":" + strconv.Itoa(*httpsPort)}
	}

	go func() {
		select {
		case <-interruptChan:
			cancel()
			srv.Shutdown(context.TODO())
			if *httpsPort > 0 {
				tlsSrv.Shutdown(context.TODO())
			}
			return
		}
	}()

	if *httpsPort > 0 {
		go func() { log.Println(tlsSrv.ListenAndServeTLS("server.crt", "server.key")) }()
	}

	log.Println(srv.ListenAndServe())
	wg.Wait()
}

const LookupPath = "lookup"
const WorkerDetailsPath = "details"
const WorkSubmit = "submit"
const WorkRetrieve = "retrieve"

const ClaimTemplate = "gettemplate"

func TheRestHandler(w http.ResponseWriter, r *http.Request) {
	defer r.Body.Close()

	w.Header().Set("Content-type", "application/json")
	path := r.URL.Path[1:]
	r.ParseForm()

	switch path {
	case LookupPath:

	case WorkerDetailsPath:

	case WorkSubmit:
		encryptCredentials(w, r)
	case WorkRetrieve:

	case ClaimTemplate:
		ct := ClaimRequestType{}
		b, _ := json.MarshalIndent(ct, "  ", "  ")
		w.Header().Set("Content-type", "application/json")
		w.Write(b)
		w.WriteHeader(http.StatusOK)
		//---------------undocumented calls---------
	case "workerdetails":
		workerDetails(w, r)
	case "workordersubmit":
		woSubmit(w, r)
	case "submit3":
		encryptCredentialsSignatureEdwards(w, r)
	//case "encryptbn256":
	//	encryptCredentialsSignatureBn256(w, r)
	case "issue":
		issueCredentials(w, r)
	case "issue3":
		issueCredentials3(w, r)
	case "newrsa":
		RsaKey()
	case "killmehard":
		os.Exit(0)
	case "pythoncode":
		pythonCode(w, r)
	case "test25519":
		genEd()
	case "decryptaes":
		decryptAESreq(w, r)
	case "striprsa":
		decryptUnlockKey(w, r)
	case "decryptsignature":
		decryptSignature(w, r)
	//case "decryptsignaturebn256":
	//	decryptSignatureBn256(w, r)
	case "verifysignature":
		verifySignature(w, r)
	default:
		dumpRequest(w, r)
	}

}

func decryptSignature(wr http.ResponseWriter, req *http.Request) {
	cred, e := readCerd3(req)
	if e != nil {
		fmt.Fprintln(wr, e)
		return
	}
	if cred.Credential.LockKey.Encrypted == true {
		fmt.Fprintln(wr, "Strip RSA encryption from the lock key first")
		return
	}
	x := new(big.Int)
	x.SetString(BankEd, 10)
	bankEdPriv := Tli(x)
	if cred.IssuerSignatureEncrytpted {
		//decrypt the signature
		pbEd, e := ParseEd25519PublicKey(cred.Credential.LockKey.Value)
		if e != nil {
			fmt.Fprintln(wr, e)
			return
		}

		//Proper private key is 32 bytes privInt + 32 bytes public point
		mockpriv := make([]byte, 64)
		copy(mockpriv, bankEdPriv[:])
		Zero := Tli(big.NewInt(0))
		ss := EdwardsScalarAddMult(bankEdPriv, pbEd, Zero)
		ciflock, e := base64.StdEncoding.DecodeString(cred.IssuerSignature)
		if e != nil {
			fmt.Fprintln(wr, e)
			return
		}
		hexplainsign, e := DecryptAES(ss[:], ciflock)
		if e != nil {
			fmt.Fprintln(wr, e)
			return
		}
		cred.IssuerSignature = string(hexplainsign)
		cred.IssuerSignatureEncrytpted = false
		b, _ := json.MarshalIndent(cred, "  ", "  ")
		wr.Write(b)

	} else {
		fmt.Fprintln(wr, "Signature not encrypted")
	}
}

/*
func decryptSignatureBn256(wr http.ResponseWriter, req *http.Request) {
	cred, e := readCerd3(req)
	if e != nil {
		fmt.Fprintln(wr, e)
		return
	}
	if cred.Credential.LockKey.Encrypted == true {
		fmt.Fprintln(wr, "Strip RSA encryption from the lock key first")
		return
	}

	if cred.IssuerSignatureEncrytpted {
		//decrypt the signature
		h, e := hex.DecodeString(cred.Credential.LockKey.Value)
		if e != nil {
			fmt.Fprintln(wr, e)
			return
		}
		ephPub := new(bn256.G1)
		_, e = ephPub.Unmarshal(h)

		if e != nil {
			fmt.Fprintln(wr, e)
			return
		}

		blindPriv := big.NewInt(0)
		blindPriv.SetString(BnPrivateLockKey, 10)
		symKeyBase := ephPub.ScalarMult(ephPub, blindPriv)

		ciflock, e := base64.StdEncoding.DecodeString(cred.IssuerSignature)
		if e != nil {
			fmt.Fprintln(wr, e)
			return
		}
		hexplainsign, e := DecryptAES(symKeyBase.Marshal()[:32], ciflock)
		if e != nil {
			fmt.Fprintln(wr, e)
			return
		}
		cred.IssuerSignature = string(hexplainsign)
		cred.IssuerSignatureEncrytpted = false
		b, _ := json.MarshalIndent(cred, "  ", "  ")
		wr.Write(b)

	} else {
		fmt.Fprintln(wr, "Signature not encrypted")
	}
}
*/

func verifySignature(wr http.ResponseWriter, req *http.Request) {
	cred, e := readCerd3(req)
	if e != nil {
		fmt.Fprintln(wr, e)
		return
	}
	if cred.Credential.LockKey.Encrypted == true {
		fmt.Fprintln(wr, "Strip RSA encryption from the lock key first")
		return
	}
	var plainsign []byte
	x := new(big.Int)
	x.SetString(BankEd, 10)
	bankEdPriv := Tli(x)

	if cred.IssuerSignatureEncrytpted {
		//decrypt the signature
		pbEd, e := ParseEd25519PublicKey(cred.Credential.LockKey.Value)
		if e != nil {
			fmt.Fprintln(wr, e)
			return
		}

		//Proper private key is 32 bytes privInt + 32 bytes public point
		mockpriv := make([]byte, 64)
		copy(mockpriv, bankEdPriv[:])
		Zero := Tli(big.NewInt(0))
		ss := EdwardsScalarAddMult(bankEdPriv, pbEd, Zero)
		ciflock, e := base64.StdEncoding.DecodeString(cred.IssuerSignature)
		if e != nil {
			fmt.Fprintln(wr, e)
			return
		}
		hexplainsign, e := DecryptAES(ss[:], ciflock)
		if e != nil {
			fmt.Fprintln(wr, e)
			return
		}
		plainsign, e = hex.DecodeString(string(hexplainsign))
		if e != nil {
			fmt.Fprintln(wr, e)
			return
		}

	} else {
		plainsign, e = hex.DecodeString(cred.IssuerSignature)
		if e != nil {
			fmt.Fprintln(wr, e)
			return
		}
	}

	isPubKey, e := ParseEd25519PublicKey(cred.IssuerPublicKey)
	if e != nil {
		fmt.Fprintln(wr, e)
		return
	}
	v, e := sVerify(isPubKey, plainsign, []byte(collectSignString(cred)))
	if e != nil {
		fmt.Fprintln(wr, e)
		return
	}
	vr := new(VerificationResponse)
	vr.Verified = v
	vrb, _ := json.MarshalIndent(vr, "  ", "  ")
	wr.Write(vrb)

}

func pythonCode(wr http.ResponseWriter, req *http.Request) {
	b, e := ioutil.ReadFile("aes-gcm-decrypt.py")
	if e != nil {
		fmt.Fprintln(wr, "error reading Python file:", e)
		return
	}
	wr.Write(b)
}

//Expect the ciphertext to be base64 encoded and the key to be hex encoded
func decryptAESreq(wr http.ResponseWriter, req *http.Request) {
	bbuf, err := ioutil.ReadAll(req.Body)
	if err != nil {
		fmt.Fprintln(wr, err)
		return

	}
	decAESreq := new(DecryptRequest)
	err = json.Unmarshal(bbuf, decAESreq)
	if err != nil {
		fmt.Fprintln(wr, err)
		return
	}

	ciphbytes, err := base64.StdEncoding.DecodeString(decAESreq.Ciphertext)
	if err != nil {
		fmt.Fprintln(wr, err)
		return
	}
	key, err := hex.DecodeString(decAESreq.Key)
	if err != nil {
		fmt.Fprintln(wr, err)
		return
	}
	plaintext, err := DecryptAES(key, ciphbytes)
	if err != nil {
		fmt.Fprintln(wr, err)
		return
	}
	fmt.Fprintf(wr, "As string: %s\n", string(plaintext))
	fmt.Fprintf(wr, "As hex: %s\n", hex.EncodeToString(plaintext))

}

func dumpRequest(wr http.ResponseWriter, req *http.Request) {

	bbuf, err := ioutil.ReadAll(req.Body)
	if err != nil {
		fmt.Fprintln(wr, err)
		return

	}
	//Dump request:
	fmt.Println("Request-----------------")
	fmt.Println("From: ", req.RemoteAddr)
	fmt.Println(req.Method, " ", req.URL)
	for k, vv := range req.Header {
		for _, v := range vv {
			fmt.Println(k, " ", v)
		}
	}
	fmt.Println(string(bbuf))

	if req.Method == http.MethodOptions {
		fmt.Println("Mocking the http OPTIONS call")
		wr.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTION")
		wr.Header().Set("Access-Control-Allow-Headers", "Content-type")
		wr.Header().Set("Content-type", "application/json")
		wr.Header().Set("Access-Control-Allow-Origin", "*")
		wr.WriteHeader(http.StatusOK)
		return
	}
}

//	"Bank Public key x" : "0x53d8775849f6eeea72adb402f64df032641ebc390e12c9fd364bbb521606e712",
//	"Bank Public key y" : "0x3152df5be7401f44ac1039cead163203ad0da687c8988c2156535430358c06c"
//   Compact Key:       6cc0580343356515c288897c68dad03a2063d1ea9c03c14af40174bef52d1503
//
//
//// Bank private key: 8922796882388619604127911146068705796569681654940873967836428543013949233636

func issueCredentials3(w http.ResponseWriter, r *http.Request) {
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
	cred := CredentialWLockVer3{}
	cred.Credential.Name = clreq.Name
	cred.Credential.DID = clreq.DID
	//TODO validate the type
	cred.Credential.Type = clreq.Type
	if len(clreq.Value) > 0 {
		cred.Credential.Value = clreq.Value
	} else {
		switch clreq.Type {
		case "Good payer cert":
			cred.Credential.Value = "Yes"
		case "Account ownership cert":
			cred.Credential.Value = "Owned by " + cred.Credential.Name
		case "Average account balance cert":
			cred.Credential.Value = "25000 EUR"
		}
	}

	if len(clreq.IssuerName) > 0 {
		cred.IssuerName = clreq.IssuerName
	} else {
		cred.IssuerName = "Santander"
	}

	if len(clreq.IssuerDID) > 0 {
		cred.IssuerDID = clreq.IssuerDID
	} else {
		cred.IssuerDID = "00042"
	}
	// TODO derive these keys
	cred.IssuerPublicKey = "6cc0580343356515c288897c68dad03a2063d1ea9c03c14af40174bef52d1503"
	cred.PublicBlindingKey = "031b55be15240db85f8fe84661c44311dff353ba160973dcec280e31d434728f023e79c3cfe7f0f752db60e5f542d8a2865a58b2568bf087751e85e00e5baf84"
	cred.IssuerSignatureEncrytpted = false

	cred.SubjecSPublicKey = PubRSA

	SignByEd3(&cred, BankEd)

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

func readCerd3(req *http.Request) (*CredentialWLockVer3, error) {
	bbuf, err := ioutil.ReadAll(req.Body)
	if err != nil {
		return nil, err

	}
	cred := new(CredentialWLockVer3)
	err = json.Unmarshal(bbuf, cred)
	if err != nil {
		return nil, err
	}
	return cred, nil
}

func decryptUnlockKey(w http.ResponseWriter, req *http.Request) {
	cred, e := readCerd3(req)
	if e != nil {
		fmt.Fprintln(w, e)
		return
	}
	privrsa, e := ParseRSAPrivKeyPEM(PrivRSA)
	if e != nil {
		fmt.Fprintln(w, e)
		return
	}
	stripRSA(cred, privrsa)
	b, e := json.MarshalIndent(cred, "  ", "  ")
	if e != nil {
		fmt.Fprintln(w, e)
		return
	}
	w.Write(b)
	return
}

func stripRSA(cred *CredentialWLockVer3, privrsa *rsa.PrivateKey) error {
	if !cred.Credential.LockKey.Encrypted {
		return fmt.Errorf("Lock key not encrypted")
	}
	ct, e := base64.StdEncoding.DecodeString(cred.Credential.LockKey.Value)
	if e != nil {
		return e
	}
	b, e := rsa.DecryptOAEP(sha256.New(), rand.Reader, privrsa, ct, []byte(RSA_ENCR_LABEL))
	cred.Credential.LockKey.Encrypted = false
	cred.Credential.LockKey.Value = string(b)
	return nil
}

func encryptJsonCredPayloadEdwards(cred *CredentialWLockVer3) (symkey string, err error) {

	//Parse Customers Public Key
	rsapub, err := crypto.ParseRSAPublicKey(cred.SubjecSPublicKey)
	if err != nil {
		return "", err
	}

	becpub, err := ParseEd25519PublicKey(cred.IssuerPublicKey)
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
	signaturebytes, err := EncryptAESString(ss[:], cred.IssuerSignature)
	if err != nil {
		return "", err
	}
	sig64base := base64.StdEncoding.EncodeToString(signaturebytes)

	cred.IssuerSignatureEncrytpted = true
	cred.IssuerSignature = sig64base
	return hex.EncodeToString(ss[:]), nil
}

/*
func ParseBn256PublicKey(bn256pbkey string) (*bn256.G1, error) {
	h, e := hex.DecodeString(bn256pbkey)
	if e != nil {
		return nil, e
	}

	gp := new(bn256.G1)
	_, e = gp.Unmarshal(h)
	if e != nil {
		return nil, e
	}

	return gp, nil
}
*/

type debuginfo struct {
	symkey  string
	ethPriv string
}

/*
func encryptJsonCredPayloadBn256(cred *CredentialWLockVer3) (di *debuginfo, err error) {

	//Parse Customers Public Key
	rsapub, err := crypto.ParseRSAPublicKey(cred.SubjecSPublicKey)
	if err != nil {
		return nil, err
	}

	becpub, err := ParseBn256PublicKey(cred.PublicBlindingKey)
	if err != nil {
		return nil, err
	}
	ephPriv, ephPub, err := bn256.RandomG1(rand.Reader)
	if err != nil {
		return nil, err
	}

	di = new (debuginfo)

	symKeySeed := becpub.ScalarMult(becpub, ephPriv)

	plaintext := hex.EncodeToString(ephPub.Marshal())
	ciphertext, _ := EncryptWithRSAKey(plaintext, rsapub)

	b64ciphertext := base64.StdEncoding.EncodeToString(ciphertext)

	cred.Credential.LockKey.Encrypted = true
	cred.Credential.LockKey.Value = b64ciphertext
	ss := symKeySeed.Marshal()[:32]
	signaturebytes, err := EncryptAESString(ss, cred.IssuerSignature)
	if err != nil {
		return nil, err
	}
	di.symkey = hex.EncodeToString(ss)
	di.ethPriv = ephPriv.String()
	sig64base := base64.StdEncoding.EncodeToString(signaturebytes)

	cred.IssuerSignatureEncrytpted = true
	cred.IssuerSignature = sig64base
	return
}

func encryptCredentialsSignatureBn256(wr http.ResponseWriter, req *http.Request) {

	cred, err := readCerd3(req)
	if err != nil {
		fmt.Fprintln(wr, err)
		return
	}

	di, err := encryptJsonCredPayloadBn256(cred)
	if err != nil {
		wr.WriteHeader(http.StatusBadRequest)
		fmt.Fprintln(wr, err)
		fmt.Println(err)
		return
	}

	ncred, err := json.MarshalIndent(&cred, "  ", "  ")
	if err != nil {
		wr.WriteHeader(http.StatusBadRequest)
		fmt.Fprintln(wr, err)
		fmt.Println(err)
		return
	}
	wr.Header().Set("Content-type", "application/json")
	//wr.Header().Set("SymAlg", "AES-256-GCM" )
	wr.Header().Add("SymKey", di.symkey)
	//wr.Header().Add("Enclave-Ed25519-private", fmt.Sprintf("%x", t) )
	//wr.Header().Add("IV", hex.EncodeToString(signaturebytes[0:12]))
	wr.WriteHeader(http.StatusOK)
	wr.Write(ncred)
}
*/
func encryptCredentialsSignatureEdwards(wr http.ResponseWriter, req *http.Request) {

	cred, err := readCerd3(req)
	if err != nil {
		fmt.Fprintln(wr, err)
		return
	}

	symkey, err := encryptJsonCredPayloadEdwards(cred)
	if err != nil {
		wr.WriteHeader(http.StatusBadRequest)
		fmt.Fprintln(wr, err)
		fmt.Println(err)
		return
	}

	ncred, err := json.MarshalIndent(&cred, "  ", "  ")
	if err != nil {
		wr.WriteHeader(http.StatusBadRequest)
		fmt.Fprintln(wr, err)
		fmt.Println(err)
		return
	}
	wr.Header().Set("Content-type", "application/json")
	wr.Header().Set("SymAlg", "AES-256-GCM")
	wr.Header().Add("SymKey", symkey)
	//wr.Header().Add("Enclave-Ed25519-private", fmt.Sprintf("%x", t) )
	//wr.Header().Add("IV", hex.EncodeToString(signaturebytes[0:12]))
	wr.WriteHeader(http.StatusOK)
	wr.Write(ncred)

}
