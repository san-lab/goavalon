package main

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io"
	"sort"

	"github.com/btcsuite/btcd/btcec"
	"github.com/san-lab/goavalon/avalonjson"
	"github.com/san-lab/goavalon/crypto"
	"github.com/san-lab/goavalon/json"
)

//A local representation of a worker
type WorkerStub struct {
	Id            string
	EncryptionKey *rsa.PublicKey
	SigningKey    *btcec.PublicKey
	Info          *avalonjson.WorkerRetrieveResult
	//TODO Handle changes and history
	sessionKey      *[32]byte
	ivsize          int
	iv              []byte //Should not commit to any fixed length
	EncryptionKeyOk bool
	SigningKeyOk    bool
	KeySignatureOK  bool

	WorkOrders map[string][]string
}

func (w *WorkerStub) CurrentSessionKey() *[32]byte {
	if w.sessionKey == nil {
		w.sessionKey = new([32]byte)
		rand.Reader.Read(w.sessionKey[:])
	}
	return w.sessionKey
}

func (w *WorkerStub) CurrentIV() []byte {
	if len(w.iv) == 0 {
		w.iv = make([]byte, w.ivsize)
		rand.Read(w.iv)
	}
	return w.iv
}

//Need to pass the Id separately, as this is external to WorkerDetails
func NewWorkerStub(wdet *avalonjson.WorkerRetrieveResult, workerId string) (*WorkerStub, error) {

	w := new(WorkerStub)
	w.WorkOrders = map[string][]string{}
	rsapub, err := crypto.ParseRSAPublicKey(wdet.Details.WorkerTypeData.EncryptionKey)
	if err != nil {
		return nil, err
	}
	w.EncryptionKey = rsapub
	w.EncryptionKeyOk = true

	ecpub, err := crypto.ParseKoblitzPubPem(wdet.Details.WorkerTypeData.VerificationKey)
	if err != nil {
		return nil, err
	}
	w.SigningKey = ecpub
	w.SigningKeyOk = true

	signature, err := crypto.DecodeECSignature(wdet.Details.WorkerTypeData.EncryptionKeySignature)
	if err != nil {
		return nil, err
	}

	if !crypto.VerifySignatureOfString(wdet.Details.WorkerTypeData.EncryptionKey, signature, ecpub) {
		return w, fmt.Errorf("Signature on the RSA key not OK!")
	}
	w.KeySignatureOK = true
	w.Id = workerId
	w.Info = wdet

	switch w.Info.Details.DataEncryptionAlgorithm {
	case "AES-GCM-256", "AES-256-GCM":

		w.ivsize = 12
	default:
		return nil, fmt.Errorf("Unsupported data encryption:", w.Info.Details.DataEncryptionAlgorithm)
	}

	return w, nil
}

func (w *WorkerStub) PrintInfo(wr io.Writer) {
	json.PrintJsonStruct(wr, w.Info)
}

func (w *WorkerStub) EncryptWOSubmitRequest(wos *avalonjson.WorkOrderSubmit) error {

	sessionKey := w.CurrentSessionKey()
	//TODO Randomize this
	rn := sha256.Sum256(sessionKey[:])
	wos.Params.RequesterNonce = hex.EncodeToString(rn[:])

	encSesKEy, err := crypto.EncryptWithRSAKey(sessionKey[:], w.EncryptionKey)

	//---Test---
	encSesKEy2, err := crypto.EncryptWithRSAKey(sessionKey[:], &EncPrivKey.PublicKey)
	fmt.Println(rsa.DecryptOAEP(sha1.New(), rand.Reader, EncPrivKey, encSesKEy2, nil))

	//--END---
	if err != nil {

		return err
	}
	wos.Params.EncryptedSessionKey = hex.EncodeToString(encSesKEy)

	switch w.Info.Details.DataEncryptionAlgorithm {
	case "AES-256-GCM", "AES-GCM-256":
		wos.Params.SessionKeyIv = hex.EncodeToString(w.CurrentIV())
		for _, inDataItem := range wos.Params.InData {
			if len(inDataItem.Data) > 0 { // Do not encrypt empty strings, or?

				datEnc, err := crypto.EncryptAESBytes(w.CurrentSessionKey()[:], w.CurrentIV(), []byte(inDataItem.Data))
				if err != nil {
					return err
				}
				inDataItem.Data = base64.StdEncoding.EncodeToString(datEnc)
			}
			if len(inDataItem.EncryptedDataEncryptionKey) > 0 { // Do not encrypt empty strings, or?

				keyEnc, err := crypto.EncryptAESBytes(w.CurrentSessionKey()[:], w.CurrentIV(), []byte(inDataItem.EncryptedDataEncryptionKey))
				if err != nil {
					return err
				}
				inDataItem.EncryptedDataEncryptionKey = base64.StdEncoding.EncodeToString(keyEnc)
			}
		}

	default:

		return fmt.Errorf("Unsupported data encryption algorithm")
	}
	//---- Hash calculation
	h := sha256.New()
	h.Write([]byte(wos.Params.RequesterNonce))
	h.Write([]byte(wos.Params.WorkOrderID))
	h.Write([]byte(wos.Params.WorkerID))
	h.Write([]byte(wos.Params.WorkloadID))
	h.Write([]byte(wos.Params.RequesterID))
	sort.Sort(avalonjson.InDataList(wos.Params.InData))
	for _, ind := range wos.Params.InData {
		h.Write([]byte(ind.DataHash))
		h.Write([]byte(ind.Data))
		h.Write([]byte(ind.EncryptedDataEncryptionKey))
		h.Write([]byte(ind.DataHash))
	}
	sort.Sort(avalonjson.OutDataList(wos.Params.OutData))
	for _, oud := range wos.Params.OutData {
		h.Write([]byte(oud.DataHash))
		h.Write([]byte(oud.Data))
		h.Write([]byte(oud.EncryptedDataEncryptionKey))
		h.Write([]byte(oud.DataHash))
	}
	hash := h.Sum(nil)
	fmt.Println(w.CurrentIV(), w.CurrentSessionKey())
	chash, err := crypto.EncryptAESBytes(w.CurrentSessionKey()[:], w.CurrentIV(), hash)
	if err != nil {
		return err
	}
	//test
	h2, err := crypto.DecryptAES(w.CurrentSessionKey()[:], w.CurrentIV(), chash)
	fmt.Println("Self-decryption test: ", bytes.Compare(hash, h2))
	wos.Params.EncryptedRequestHash = hex.EncodeToString(chash)

	return nil
}

func (w *WorkerStub) PrintStatus(wr io.Writer) {
	fmt.Fprintln(wr, "RSA key parsed:\t\t", w.EncryptionKeyOk)
	fmt.Fprintln(wr, "EC key parsed:\t\t", w.SigningKeyOk)
	fmt.Fprintln(wr, "Key signature check:\t", w.KeySignatureOK)
	fmt.Fprintln(wr, "Session key:", hex.EncodeToString(w.CurrentSessionKey()[:]))

}
