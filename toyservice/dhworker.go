package toyservice

import (

	"encoding/json"
	"crypto/sha256"
	"encoding/hex"
	"crypto/rand"
)




func (wrk *Worker) EncryptDalionStyle(request *GenericAvalonRPCRequest, response *GenericResponse) {
	switch request.Method {
	case WorkerRetrieve:
		wrk.handleDetails(request,response)
	case WorkOrderSubmitMethod:
		wrk.handleSubmit(request, response)
	default:
		rm := request.Params
		params := new(WOSubmitParams)
		json.Unmarshal(rm, params)
		locRes := new (WorkOrderSubmitResult)
		locRes.OutData = make([]OutData, 1)
		locRes.OutData[0].Data = "Got here!"


		b, _ := json.Marshal(locRes)
		response.Result = b
	}


}

func (wrk *Worker) handleDetails (request *GenericAvalonRPCRequest, response *GenericResponse) {
	locRes := WorkerRetrieveResult{}
	locRes.OrganizationID = hex.EncodeToString(wrk.OrganizationID[:])
	locRes.WorkerType = Type1
	locRes.Status = 1
	locRes.Details.HashingAlgorithm =  "SHA-256"
	locRes.Details.SigningAlgorithm = "SECP256K1"
	locRes.Details.KeyEncryptionAlgorithm = "RSA-OAEP-3072"
	locRes.Details.DataEncryptionAlgorithm = "AES-GCM-256"
	locRes.Details.WorkOrderPayloadFormats = "JSON-RPC"
	locRes.Details.WorkerTypeData.EncryptionKey = ServPubRSA
	//---Remove this after verification
	privkey, _ := ParseKoblitzPrivPem(ServPrivEC)
	pb := EcPubKeyBytesToPem(privkey.PubKey().SerializeUncompressed())


	locRes.Details.WorkerTypeData.VerificationKey = pb
	locRes.Details.WorkerTypeData.EncryptionKeySignature = "z"

	b, _ := json.Marshal(locRes)
	response.Result = b
}

func (wrk *Worker) handleSubmit (request *GenericAvalonRPCRequest, response *GenericResponse) {
	subPar := new(WOSubmitParams)
	json.Unmarshal(request.Params, subPar)

	locRes := WorkOrderSubmitResult{}
	locRes.WorkOrderID = subPar.WorkOrderID
	locRes.RequesterID = subPar.RequesterID
	locRes.WorkloadID = subPar.WorkloadID
	locRes.WorkerID = hex.EncodeToString(wrk.ID[:])
	locRes.WorkerNonce = getNonce()

	locRes.OutData = []OutData{}


	b, _ := json.Marshal(locRes)
	response.Result = b
}


func getNonce() string {
	buf := make([]byte, 32)
	rand.Read(buf)
	return hex.EncodeToString(buf)
}

func NewEncryptorWorker() *Worker {
	w := new(Worker)
	w.Type = Type1
	w.Process = w.EncryptDalionStyle
	w.OrganizationID = ACMEID
	w.ID = [32]byte{}
	copy(w.ID[:], sha256.New().Sum([]byte("dh-encryptor")))
	return w
}