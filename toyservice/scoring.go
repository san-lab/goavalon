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

var encryptRequestTest = `{"scoring": "score",
"clientpubkey":"cpk",
"issuerpubkey":"ipk"}`

type EncryptRequest struct {
	Scoring      Scoring `json:"scoring"`
	Clientpubkey string  `json:"clientpubkey"`
	Issuerpubkey string  `json:"issuerpubkey"`
}


//------------from G&P------------------

type PlainCredentialType struct {
	Type  string `json:"Type"`
	Name  string `json:"Name"`
	DID   string `json:"DID"`
	Score struct {
	Encrypted bool   `json:"encrypted"`
	Value     string `json:"value"`
} `json:"score"`
}



type LockKeyType struct {
	Encrypted bool   `json:"encrypted"`
	Value     string `json:"value"`
}

type CredentialWLock struct {
	Credential struct {
		Type  string `json:"Type"`
		Name  string `json:"Name"`
		DID   string `json:"DID"`
		Score struct {
			Encrypted bool   `json:"encrypted"`
			Value     string `json:"value"`
		} `json:"score"`
		LockKey LockKeyType `json:"lock key"`
	} `json:"Credential"`
	BankPublicKey BankPubKeyType `json:"Bank public key"`
	SubjecSPublicKey string `json:"Subject's Public key"`
}

type BankPubKeyType struct {
		BankPublicKey  string `json:"Bank Public key,omitempty"`
		BankPublicKeyX string `json:"Bank Public key x,omitempty"`
		BankPublicKeyY string `json:"Bank Public key y,omitempty"`

}