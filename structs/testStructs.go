package structs

import (
	"encoding/json"
	"fmt"
)

func TestWorker () {
	wl := new(WorkerLookupResponse)
	b := []byte(workerLookupResponseTest)
	TestStruct(wl,b)
}

func TestRetrieveResponse () {
	wl := new(WorkerRetrieveResponse)
	b := []byte(workerRetrieveResponseTest)
	TestStruct(wl,b)
}



func TestStruct (i interface{}, testBytes []byte) {

	e := json.Unmarshal(testBytes, i)
	if e != nil {
		fmt.Println(e)
	}

	b,e := json.MarshalIndent(i, " ", " ")
	if e != nil {
		fmt.Println(e)
	}
	fmt.Println(string(b))
}
