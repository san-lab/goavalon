package toyservice


var scoreTest = `{
"Type":"Credit Scoring",
"Name": "Some Name",
"DID": "Some DID",
"score": {"encrypted": true, "value": "v"},
"lock key": {"encrypted": true, "value": "v"}
}`

type Scoring struct {
	Type  string `json:"Type"`
	Name  string `json:"Name"`
	DID   string `json:"DID"`
	Score struct {
		Encrypted bool   `json:"encrypted"`
		Value     string `json:"value"`
	} `json:"score"`
	LockKey struct {
		Encrypted bool   `json:"encrypted"`
		Value     string `json:"value"`
	} `json:"lock key"`
}


var encryptRequestTest =`{"scoring": "score",
"clientpubkey":"cpk",
"issuerpubkey":"ipk"}`

type EncryptRequest struct {
	Scoring      Scoring `json:"scoring"`
	Clientpubkey string  `json:"clientpubkey"`
	Issuerpubkey string  `json:"issuerpubkey"`
}
