package main

import (
	"encoding/json"
	"fmt"
	"io/ioutil"

	"github.com/san-lab/goavalon/avalonjson"

	"crypto/rand"
	"encoding/hex"
	"os"

	json2 "github.com/san-lab/goavalon/json"
)

func InvokeHeartDiagDemo(stub *WorkerStub) {
	wos, e := readJsonTemplate("heart-disease-plain.json")
	if e != nil {
		fmt.Println(e)
		return
	}
	wos.Params.WorkerID = stub.Id
	wos.Params.WorkloadID = WorkLoads[a]
	woid := make([]byte, 8)
	rand.Read(woid)
	wos.Params.WorkOrderID = hex.EncodeToString(woid)
	if heartOrders, ok := stub.WorkOrders[a]; ok {

		stub.WorkOrders[a] = append(heartOrders, wos.Params.WorkOrderID)
	} else {

		heartOrders = []string{wos.Params.WorkOrderID}
		stub.WorkOrders[a] = heartOrders
	}
	//wos.Params.WorkerEncryptionKey = stub.Info.Details.WorkerTypeData.EncryptionKey
	stub.EncryptWOSubmitRequest(wos)
	g, e := HC.WorkOrderSubmitCall(wos)
	fmt.Println("WOS returned error:", e)
	json2.PrintJsonStruct(os.Stdout, g)

}

func readJsonTemplate(filename string) (*avalonjson.WorkOrderSubmit, error) {
	b, e := ioutil.ReadFile("../json/" + filename)
	if e != nil {

		return nil, e
	}
	wos := new(avalonjson.WorkOrderSubmit)
	e = json.Unmarshal(b, wos)
	if e != nil {
		return nil, e
	}
	return wos, nil
}
