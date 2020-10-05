package toyservice

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"github.com/san-lab/goavalon/avalonjson"
)

func (wrk *Worker) EncryptDalionStyle(request *avalonjson.GenericAvalonRPCRequest, response *avalonjson.GenericResponse) {
	switch request.Method {
	case WorkerRetrieve:
		wrk.handleDetails(request, response)
	case WorkOrderSubmitMethod:
		wrk.handleSubmit(request, response)
	default:
		rm := request.Params
		params := new(avalonjson.WOSubmitParams)
		json.Unmarshal(rm, params)
		locRes := new(avalonjson.WorkOrderSubmitResult)
		locRes.OutData = make([]*avalonjson.OutDataItem, 1)
		locRes.OutData[0].Data = "Got here!"

		b, _ := json.Marshal(locRes)
		response.Result = b
	}

}

type Worker struct {
	ID              [32]byte //32 bytes
	Type            int
	ApplicationType int
	OrganizationID  [32]byte //32 bytes
	Process         func(request *avalonjson.GenericAvalonRPCRequest, response *avalonjson.GenericResponse)
}

func (wrk *Worker) handleDetails(request *avalonjson.GenericAvalonRPCRequest, response *avalonjson.GenericResponse) {
	locRes := avalonjson.WorkerRetrieveResult{}
	locRes.OrganizationID = hex.EncodeToString(wrk.OrganizationID[:])
	locRes.WorkerType = Type1
	locRes.Status = 1
	locRes.Details.HashingAlgorithm = "SHA-256"
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

func (wrk *Worker) handleSubmit(request *avalonjson.GenericAvalonRPCRequest, response *avalonjson.GenericResponse) {
	subPar := new(avalonjson.WOSubmitParams)
	json.Unmarshal(request.Params, subPar)

	locRes := avalonjson.WorkOrderSubmitResult{}
	locRes.WorkOrderID = subPar.WorkOrderID
	locRes.RequesterID = subPar.RequesterID
	locRes.WorkloadID = subPar.WorkloadID
	locRes.WorkerID = hex.EncodeToString(wrk.ID[:])
	locRes.WorkerNonce = getNonce()

	locRes.OutData = []*avalonjson.OutDataItem{}

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
