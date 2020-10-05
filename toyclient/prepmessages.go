package main

import (
	"crypto/rand"
	"github.com/san-lab/goavalon/avalonjson"
)

func EncryptSubmit(req *avalonjson.WOSubmitParams) {

	sessionkey := make([]byte, 32)
	rand.Read(sessionkey)

	iv := make([]byte, 12)
	rand.Read(iv)

	for _, v := range req.InData {
		ptext := []byte(v.Data)
		ptext = append(iv, ptext...)
		//toyservice.EncryptAESString()

	}

}
