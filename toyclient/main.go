package main

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"

	"github.com/manifoldco/promptui"
	"github.com/san-lab/goavalon/avalonjson"
	"github.com/san-lab/goavalon/crypto"
	json2 "github.com/san-lab/goavalon/json"
)

const exit = "EXIT"
const up = "UP"
const endpoint = "Set Avalon Endpoint"

//This is ugly, but no const stucts in Go :-/
type meth struct {
	WorkerLookUp, WorkerRetrieve, WorkOrderGetResult string
}

var methods = meth{
	WorkerLookUp:       "WorkerLookUp",
	WorkerRetrieve:     "WorkerRetrieve",
	WorkOrderGetResult: "WorkOrderGetResult",
}

func main() {
	initClient("http://40.120.61.169:8200")
	for {
		//TODO That is a hack I use only because I do not know the framework yet :-(
		prompt := promptui.SelectWithAdd{
			Label:    "Select Action on " + HC.AvalonEndpoint,
			Items:    []string{methods.WorkerLookUp, "test", exit},
			AddLabel: endpoint,
		}

		index, result, err := prompt.Run()

		if err != nil {
			fmt.Printf("Prompt failed %v\n", err)
			return
		}
		if index == -1 {
			initClient(result)
		}

		switch result {
		case methods.WorkerLookUp:
			workerLookup()
		case "test":
			test()
		case exit:
			fmt.Println("Thanks for using GoAvalonClient")
			return
		}

	}
}

func workloadListMenu(w *WorkerStub) {
	for {
		prompt := promptui.Select{
			Label: "Select a Workload",
			Items: []string{a, b, up},
		}

		_, result, err := prompt.Run()

		if err != nil {
			fmt.Printf("Prompt failed %v\n", err)
			return
		}
		switch result {
		case up:
			return
		case a, b:
			workloadMenu(result, w)
		default:
			fmt.Println(hex.EncodeToString([]byte(result)))
		}

	}
}

func workloadMenu(workload string, stub *WorkerStub) {
	for {

		prompt := promptui.Select{
			Label: "Existing WorkOrders for >>" + workload + "<<",
			Items: append(stub.WorkOrders[workload], "New WorkOrder", up),
		}

		_, result, err := prompt.Run()

		if err != nil {
			fmt.Printf("Prompt failed %v\n", err)
			return
		}

		switch result {
		case "New WorkOrder":
			InvokeHeartDiagDemo(stub)
		case up:
			return
		default:
			gres, _ := GetWOResult(result)
			json2.PrintJsonStruct(os.Stdout, gres)

		}

	}
}

func workerLookup() {
	rs, e := HC.WoLookup()
	if e != nil {
		fmt.Println(e)
		return
	}
	selectWorker(rs)

}

func selectWorker(alr *avalonjson.WorkerLookupResult) {
	prompt := promptui.Select{
		Label: "Available Workers (select for details)",
		Items: alr.Ids,
	}
	prompt.Items = append(prompt.Items.([]string), up)

	_, result, err := prompt.Run()

	if result == up {
		return
	}

	if err != nil {
		fmt.Printf("Prompt failed %v\n", err)
		return
	}

	wrdr, _ := workerDetails(result)
	workerMenu(wrdr)
}

func workerMenu(w *WorkerStub) {
	prompt := promptui.Select{
		Label: "Worker " + w.Id,
		Items: []string{"Status", "Details", "Invoke", up},
	}
	for {
		_, result, err := prompt.Run()
		if err != nil {
			fmt.Printf("Prompt failed %v\n", err)
			return
		}

		switch result {
		case "Status":
			w.PrintStatus(os.Stdout)
		case up:
			return
		case "Details":
			w.PrintInfo(os.Stdout)
		case "Invoke":
			workloadListMenu(w)
		default:

		}
	}

}

func workerDetails(workerId string) (*WorkerStub, error) {
	greq := new(avalonjson.GenericAvalonRPCRequest)
	greq.Method = methods.WorkerRetrieve
	par := new(avalonjson.WorkerRetrieveParams)
	par.WorkerID = workerId
	b, _ := json.Marshal(par)
	greq.Params = b
	res, err := HC.genericRPCCall(greq)
	if err != nil {
		fmt.Println(err)
		return nil, err
	}
	wordit := new(avalonjson.WorkerRetrieveResult)
	err = json.Unmarshal(res.Result, wordit)
	if err != nil {
		fmt.Println(err)
		return nil, err
	}
	//fmt.Println(wordit)
	w, err := NewWorkerStub(wordit, workerId)
	if err != nil {
		fmt.Println("Error parsing details:", err)

	}
	return w, nil
}

func test() {
	prv, _ := crypto.ParseRSAPrivateKey(Eprv)
	pb, _ := crypto.ParseRSAPublicKey(E1)

	fmt.Println(prv.PublicKey)
	fmt.Println(pb)
}

var iv = "4dbf42f8789d3c5be2c8eb27"
var key = "52379fb277bc1b13bba0712320765a7066834eb84f12ee35b269ecb79441e9e7"
var ehash = "bd8a85a5c57d40bd07daa6ae433324c4f3b09b66af66c404107a028b31a7f33fbf7aa20c6bb29b93aa9331de7b7253b8"

var E1 = `-----BEGIN PUBLIC KEY-----
MIIBojANBgkqhkiG9w0BAQEFAAOCAY8AMIIBigKCAYEAuP1xLwLDjZG3wlgFT39Q
RT5oIhr75rdaiIpohW3NX4XnSSwIZflicqC683CtN35NviQhYzYe+ccqglIYqj4s
spiasIS6CyQQ2WMBL5/oIMmTu7rCV/524i0yaNHRjAPPT5GZd79dF9J+frR9JYof
CLg1xWcMjOTvvoKgXzerX56YVeBCnrmR6guC9odL6C83cNeMpmRO/ZO4SSQ3prrg
rPh+N3TPgf+VWbFEXXg4ybC0XJ8H3qTZvyuFycX7cdH3gF7hxcZYEX1OrgA8mrRX
nhurM3eR+TNtTTo9sQ4OJtPKOd8BZ2YRYrNDJr+sTetwNMBP03JP/v9YaXTKEOGm
15Vk5J2JEala6ZkbVsJv5FZqK4nOHTsuLk3NtBzWyQKj1e1TPMDb2Q7WleDCTnyt
JlostVRLPutYhCGrEUlR6f/Ux7f24abpb0NuNL88ifgeMlKrG2LxM9M40XBCotfD
DQr7eJXvVPKjLnU+AQo1GULy0o7f7eNmhnMHXzmCrgsWrAgMBAAE=
-----END PUBLIC KEY-----`

var e2 = `-----BEGIN PUBLIC KEY-----\nMIIBojANBgkqhkiG9w0BAQEFAAOCAY8AMIIBigKCAYEA0S08/ScRotgX8e+NtUWZ\nfJ47bW+807f6xfJR++t0Y0E2UBt2E1mpD980CDSO4BtTmsiVuKTOfJL+Ll+PG8TM\nEY9iPRmrm17u0AvyGaq6Ibr44FVre+O6ZsmJsVou5S56iqBZBWbAUtJ/XYMQjgpB\n84GWuM9h5+YjdCupwd8ZvgRDEAKGWhCcv9uxzmGjnpusCzZZau6k9SfK5N0yErik\nnsckY2vbGb4o95jRh4xaTFuSIt4hAlrBpBUx6DrE3sHc9rcVArIrMpg13VNBrOP6\nkUcCyii88AEiRjUZGGKob1cpsKN+m4PLxKVeUqC6bIUn+jmjZoBaKJ0lb7k8MTQk\njQxif4hVkuPZPTMd6toOhHLcrKEH5BO1rsts6z0rOMm6XTUycADK0oYxnIOYkr25\nDDYMa4x6qaY9cby1lrkHvOGUGTAFchklLdkaJh+oPHz9LKxJbNYAx72Xl8DmMZ0N\nqxvcQfNcQwEIg7ZxsnNcSzbOr6l1d5T/bwumXyLPgba9AgMBAAE=\n-----END PUBLIC KEY-----\n`
var Eprv = `-----BEGIN RSA PRIVATE KEY-----
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
-----END RSA PRIVATE KEY-----`
