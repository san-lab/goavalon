package toyservice

import (
	"flag"
	"os"
	"sync"
	"net/http"
	"os/signal"
	"strconv"
	"log"
	"context"
	"fmt"
	"io/ioutil"
	"encoding/json"
	"crypto/rand"
	"encoding/hex"
	"math/big"
	"encoding/base64"
)

func StartServer() {
	httpPort := flag.String("httpPort", "8080", "http port")
	httpsPort := flag.Int("httpsPort", 0, "https port. tls not started if not provided. requires server.crt & server.key")
	flag.Parse()

	//thehandler.InTEE = myrsa.Initkeys()
	//thehandler.Renderer = templates.NewRenderer()
	interruptChan := make(chan os.Signal)
	wg := &sync.WaitGroup{}
	ctx := context.Background()
	ctx, cancel := context.WithCancel(ctx)
	ctx = context.WithValue(ctx, "WaitGroup", wg)
	fs := http.FileServer(http.Dir("static"))
	http.HandleFunc("/static/", http.StripPrefix("/static", fs).ServeHTTP)
	signal.Notify(interruptChan, os.Interrupt)

	http.HandleFunc("/", TheHandler)

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

func TheHandler(w http.ResponseWriter, r *http.Request) {
	defer r.Body.Close()

	path := r.URL.Path[1:]
	r.ParseForm()

	switch path {
	case LookupPath:

	case WorkerDetailsPath:

	case WorkSubmit:
		encryptCredentials(w,r)
	case WorkRetrieve:
//---------------undocumented calls---------
	case "issue":
		issueCredentials(w,r)
	case "newrsa":
		RsaKey()
	case "killmehard":
		os.Exit(0)
	case "test25519":
		TestEd()
	default:
		dumpRequest(w,r)
	}

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

func issueCredentials(w http.ResponseWriter, r *http.Request) {
	fmt.Println("issuing")
	w.Header().Set("Content-Type", "application/json")
	cred := CredentialWLock{}

	cred.Credential.Name = "Alice"
	cred.Credential.DID = "42"
	cred.Credential.Type = "Credit scoring"

	cred.BankPublicKey.BankPublicKeyX = "53d8775849f6eeea72adb402f64df032641ebc390e12c9fd364bbb521606e712"
	cred.BankPublicKey.BankPublicKeyY = "03152df5be7401f44ac1039cead163203ad0da687c8988c2156535430358c06c"
	cred.BankPublicKey.BankPublicKey = "6cc0580343356515c288897c68dad03a2063d1ea9c03c14af40174bef52d1503"

	cred.Credential.Score.Encrypted = false
	cred.Credential.Score.Value = "A Plus"

	cred.SubjecSPublicKey = PubRSA

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


func encryptCredentials (wr http.ResponseWriter, req *http.Request) {

	bbuf, err := ioutil.ReadAll(req.Body)
	if err != nil {
		fmt.Fprintln(wr, err)
		return

	}
	cred := new(CredentialWLock)
	err = json.Unmarshal(bbuf, cred)
	if err != nil {
		fmt.Fprintln(wr,err)
		return
	}


	//Parse Customers Public Key
	rsapub, err := ParseRSAPublicKey(cred.SubjecSPublicKey)
	if err != nil {
		wr.WriteHeader(http.StatusBadRequest)
		fmt.Fprintln(wr, err)
		fmt.Println(err)
		return
	}



	becpub, err := ParseEd25519PublicKey(cred.BankPublicKey)
	fmt.Println(hex.EncodeToString(becpub[:]),err)

	//TODO Use seed as Ed usually does
	ephEd25519private := make([]byte, 32)
	rand.Reader.Read(ephEd25519private)
	ephEd25519private[0] &=127 //This should work instead of actual MOD
	//fmt.Println(hex.EncodeToString(ephEd25519private[:]))

	t := new(big.Int)
	t.SetBytes(ephEd25519private)
	ephPrivInternal := Tli(t)
	ephEdpublic := EdwardsScalarMultB(ephPrivInternal)

	fmt.Println(hex.EncodeToString(ephEdpublic[:]))

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

	cred.Credential.LockKey.Encrypted=true
	cred.Credential.LockKey.Value=b64ciphertext

	//TODO: Handle different block types, do not assume len(ss)==32
	scorebytes, err := EncryptAES(ss[:], cred.Credential.Score.Value)
	if err != nil {
		wr.WriteHeader(http.StatusBadRequest)
		fmt.Fprintln(wr, err)
		fmt.Println(err)
		return
	}
	score64base := base64.StdEncoding.EncodeToString(scorebytes)

	cred.Credential.Score.Encrypted=true
	cred.Credential.Score.Value = score64base

	ncred, err := json.MarshalIndent(&cred, "  ", "  " )
	if err != nil {
		wr.WriteHeader(http.StatusBadRequest)
		fmt.Fprintln(wr, err)
		fmt.Println(err)
		return
	}
	wr.Header().Set("Content-type", "application/json")
	wr.Header().Set("SymAlg", "AES-256-GCM" )
	wr.Header().Add("SymKey", hex.EncodeToString(ss[:]))
	wr.Header().Add("Enclave-Ed25519-private", fmt.Sprintf("%x", t) )
	wr.Header().Add("IV", hex.EncodeToString(scorebytes[0:12]))
	wr.WriteHeader(http.StatusOK)
	wr.Write(ncred)





}



