package main

import (
	"bytes"
	"encoding/json"
	"github.com/san-lab/goavalon/avalonjson"
	"io/ioutil"
	"net/http"
	"crypto/rsa"
	"fmt"
	"github.com/san-lab/goavalon/crypto"
)

//Implicit init of JSONRPC sequence
func initClient(url string) {
	HC = new(Client)
	HC.httpClient = new(http.Client)
	HC.AvalonEndpoint = url
	hack()
}

func hack() {
	b,e := ioutil.ReadFile("../crypto/enclave.pem")
	if e != nil {
		fmt.Println(e)
		return
	}
	EncPrivKey, e = crypto.ParseRSAPrivateKey(string(b))
	if e != nil {
		fmt.Println(e)
		return
	}
}

var EncPrivKey *rsa.PrivateKey

var HC *Client

//A rest api client, wrapping an http client
type Client struct {
	AvalonEndpoint string // host:port
	UserAgent      string
	httpClient     *http.Client
	seq            int
	DebugMode      bool
	dumpRPC        bool
}

//TODO pass lookup parameter, and process them
func (hc *Client) WoLookup() (*avalonjson.WorkerLookupResult, error) {
	wlup := avalonjson.WorkerLookupParams{}
	wlup.WorkerType = 1
	//wlup.OrganizationID = ""
	//wlup.ApplicationTypeID = 0
	//"{"jsonrpc": "2.0", "method": "WorkerLookUp", "id": 1, "params": {"workerType": 1, "workOrderId": null}}

	reqj := new(avalonjson.GenericAvalonRPCRequest)
	reqj.Method = "WorkerLookUp"
	err := reqj.SetParams(wlup)
	reqj.Params, err = json.Marshal(wlup)
	if err != nil {
		return nil, err
	}

	res, err := hc.genericRPCCall(reqj)
	if err != nil {
		return nil, err
	}
	wores := new(avalonjson.WorkerLookupResult)

	err = json.Unmarshal(res.Result, wores)
	if err != nil {
		return nil, err
	}

	return wores, err
}

func  GetWOResult( woid string ) (*avalonjson.GenericResponse, error) {
	worReq := new(avalonjson.GenericAvalonRPCRequest)
	worReq.Method = methods.WorkOrderGetResult
	woParams := new(avalonjson.WOGetResultParams)
	woParams.WorkOrderID = woid
	worReq.SetParams(woParams)
	return HC.genericRPCCall(worReq)

}




func (hc *Client) genericRPCCall(reqj *avalonjson.GenericAvalonRPCRequest) (*avalonjson.GenericResponse, error) {
	hc.seq++
	reqj.ID = hc.seq
	reqj.Jsonrpc = "2.0"
	jsonreq, _ := json.Marshal(reqj)
	req, err := http.NewRequest("POST", hc.AvalonEndpoint, bytes.NewReader(jsonreq))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "GoAvalon")
	req.Header.Set("Content-type", "application/json")

	res, err := HC.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()
	rbytes, err := ioutil.ReadAll(res.Body)

	gres := new(avalonjson.GenericResponse)
	err = json.Unmarshal(rbytes, gres)
	return gres, err

}

func (hc *Client) WorkOrderSubmitCall(reqj *avalonjson.WorkOrderSubmit) (*avalonjson.GenericResponse, error) {
	hc.seq++
	reqj.ID = hc.seq
	reqj.Jsonrpc = "2.0"
	jsonreq, _ := json.Marshal(reqj)
	req, err := http.NewRequest("POST", hc.AvalonEndpoint, bytes.NewReader(jsonreq))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "GoAvalon")
	req.Header.Set("Content-type", "application/json")

	res, err := HC.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()
	rbytes, err := ioutil.ReadAll(res.Body)

	gres := new(avalonjson.GenericResponse)
	err = json.Unmarshal(rbytes, gres)
	return gres, err

}

