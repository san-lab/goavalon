package toyservice

import (
	"context"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"encoding/hex"
	"bytes"
	"encoding/base64"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/rand"
	"github.com/btcsuite/btcd/btcec"
)

const Type1 = 1 // indicates "TEE-SGX": an Intel SGX Trusted Execution Environment
const Type2 = 2 // indicates "MPC": Multi-Party Compute
const Type3 = 3 // indicates "ZK": Zero-Knowledge

const GoAvalonPath = "goavalon"
const Lookup = "WorkerLookUp"
const WorkerRetrieve  = "WorkerRetrieve"
const WorkOrderSubmitMethod = "WorkOrderSubmit"
const WorkOrderGetResultMethod = "WorkOrderGetResult"

var ACMEID = [32]byte{0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,42}

type GoAvalon struct {
	Ctx     context.Context
	workers map[string]*Worker
	rsaKey *rsa.PrivateKey
	ecKey  *btcec.PrivateKey
}

func NewService(ctx context.Context) *GoAvalon {
	//TODO singleton implementation
	gav := new(GoAvalon)
	gav.Ctx = ctx
	gav.init()
	return gav
}

func (gav *GoAvalon) init() {
	gav.workers = map[string]*Worker{}
	var err error
	gav.rsaKey, err = ParseRSAPrivKeyPEM(ServPrivRSA)
	fmt.Println(err)
	gav.ecKey, err = ParseKoblitzPrivPem(ServPrivEC)
	fmt.Println(err)

	gav.addWorker( NewEncryptorWorker() )
}

func (gav *GoAvalon) addWorker(w *Worker) {
	gav.workers[hex.EncodeToString(w.ID[:])] = w
}



func (gav *GoAvalon) TheHandler(w http.ResponseWriter, r *http.Request) {
	//TODO? Verify app/json content type
	defer r.Body.Close()
	w.Header().Set("Content-type", "application/json")

	//We do it once here for all methods, so in-lining
	bbuf, err := ioutil.ReadAll(r.Body)
	greq := new(GenericAvalonRPCRequest)
	err = json.Unmarshal(bbuf, greq)
	if err != nil {
		fmt.Fprintln(w, err)
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	gres := new(GenericResponse)
	gres.ID = greq.ID
	//TODO? Verify these
	gres.Jsonrpc = greq.Jsonrpc

	//Subroutines should modify the GenericResponse object, which will be marshalled out
	//TODO: handle json errors
	switch greq.Method {
	case Lookup:
		gav.WorkerLookup(greq, gres)
	case WorkerRetrieve, WorkOrderSubmitMethod:
		wrp := new(WorkerRetrieveParams)
		json.Unmarshal(greq.Params, wrp)
		wrk, is := gav.workers[wrp.WorkerID]
		if ! is {
			w.WriteHeader(http.StatusBadRequest)
			fmt.Fprintln(w,"No such worker:", wrp.WorkerID)
			return
		}
		wrk.Process(greq, gres)
	default:
	}
	b, _ := json.Marshal(gres)
	w.WriteHeader(http.StatusOK)
	w.Header().Set("Content-type", "application/json")
	fmt.Fprintln(w,string(b))
}


func (gav *GoAvalon) WorkerLookup(request *GenericAvalonRPCRequest, response *GenericResponse) {
	woloopar := new(WorkerLookupParams)
	json.Unmarshal(request.Params,woloopar)
	woloor := new (WorkerLookupResult)
	found := make([]string, 0, len(gav.workers))
	var oid []byte
	if len(woloopar.OrganizationID) > 0 {
		oid, _ = hex.DecodeString(woloopar.OrganizationID)
	}
	for id, wrk := range gav.workers {
		if woloopar.ApplicationTypeID ==0 || wrk.ApplicationType == woloopar.ApplicationTypeID {
			if len(woloopar.OrganizationID) ==0 || bytes.Equal( wrk.OrganizationID[:] , oid) {
				found = append(found, id)
			}
		}
	}
	woloor.Ids=found
	woloor.TotalCount = len(found)
	b,_ := json.Marshal(woloor)
	response.Result = b

}

func (gav *GoAvalon) DecryptInData(subDat *WOSubmitParams) error {



	encskey, err := base64.StdEncoding.DecodeString(subDat.EncryptedSessionKey)

	sessionkey, err := rsa.DecryptOAEP(sha256.New(), rand.Reader, gav.rsaKey, encskey, nil)
	if err != nil {
		return err
	}
	iv, err := hex.DecodeString(subDat.SessionKeyIv)
	if err != nil {
				return err
	}
	for i, _ := range subDat.InData {
		ctdata, err := base64.StdEncoding.DecodeString(subDat.InData[i].Data)
		if err != nil {
			return err
		}
		ctdata = append(iv, ctdata...)

		ptdata, err := DecryptAES(sessionkey, ctdata)
		if err != nil {
			return err
		}

		subDat.InData[i].Data =  hex.EncodeToString(ptdata)
	}
	return nil

}
