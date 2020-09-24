package toyclient

import (
	"github.com/san-lab/goavalon/toyservice"
	"crypto/rand"
)

func EncryptSubmit(req *toyservice.WOSubmitParams) {

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
