package structs

//-----------------------------------------------
var workOrderSubmitTest = `{
    "jsonrpc": "2.0",
    "method": "WorkOrderSubmit",
    "id": 32,
    "params": {
        "workOrderId": "9d44c6f7a310e2abdcfa23cef7a507658a68bbac8665b8162e53af187c2ca46f",
        "responseTimeoutMSecs": 6000,
        "payloadFormat": "JSON-RPC",
        "resultUri": " ",
        "notifyUri": " ",
        "workerId": "ad8ef7abd63076b74175d49e3db3087da1c6f46ff8912a87cb354c816a6ad26b",
        "workloadId": "6563686f2d726573756c74",
        "requesterId": "e20e576e6835efa179fdddf677cae1111d94f620e1e4946ce2a2833003df9d8e",
        "workerEncryptionKey": "2d2d2d2d2d424547494e205055424c4943204b45592d2d2d2d2d0a4d4949426f6a414e42676b71686b6947397730424151454641414f43415938414d49494269674b4341594541774a4d364166396f656f7042674449654477696f0a51687061525132676f5730424b5965786b75586b2f5477524b693254776369417a54676a496d736147576230507643555a664e3035426d564f6b52436c5878370a72504469665a3678546950487965722f714d537862784b4d342f545256445454725938514875634359596534797056575a5331454350417a516e7a796b502b520a6552364736367a527a4755696e456538372f382f393767535831416e3443396b474a342f6375375a2b4467323473535676582f424a384f3779496f31355261650a3735614555372b723934486d6d7736596774344e585a614b4f594e523532524f766e354c724a4b3669446269634c437839356f46747747564c6b6f304e5870380a66394e7844786e36506e5867342f63513532656b63453365705a6f6565314449653865653547557a6c6945644a4568735a356d3630774261453832322b42396f0a49526b3259776539544c7a746b43596d694967495a6e5532514375326c6c7832695a7a7741544e7457544e45667647666f457648366c4d717231567a6a3763360a654b59416154746f46524d41784d39546d48696855564d4174696a34786552664e6647354f50476f48674d3156486438525741504830506b5147534271557a650a694c517346456a78535278624648332f35784d55506952484d6245486e4c75434a2f4e44434858345644715041674d424141453d0a2d2d2d2d2d454e44205055424c4943204b45592d2d2d2d2d0a",
        "dataEncryptionAlgorithm": "AES-GCM-256",
        "encryptedSessionKey": "02D9FC140FD3F99EFE82F5594C28ACAFBD188525EDEA948A70BCD9FD015D3086C1CCEF7406F6DB17C41642D14508FE8747E37D0F398F9BD2809F713BE504937E426D6872AB9D0623EE71030D372D598D6815B401D60434BCBE5AC8EC6FF9EF998AE097EE6DC2889D6BA7E0B27C384B784D256B252EEC7A3290835082A234BD24ED41EC75F86300C5A76C25950CC028114E0DFF7FFF0F172226789F3DC1AA0A33EDC0270622C48FD1BD5C450C834B1526E160CDE49B799B5C1E34977BBA48C64B612CFADD2F820EC7A7A10CAD641BCCC8C9D299EC1888E053E594AA52608093596E7BC0040818F3D8626FCC056E79723DE697982A266C80D488BE97E7AF09908A78D25317A83887CBF429D3801DF6CD1FDAD7F741294294FB7B970EC6F32A7A23FD88F993E40218BF6C15A8B4B9F2D289B9D204ECC38DDDD71CD648228948A482C378C370C7A3115E6ED498444B464C5C2CFC0FE9F47395167B5AEB2151FD97A143EB966EEB88F95556F6275223D143C245966A3ACE32100EE1A23A17D9A49DE2",
        "sessionKeyIv": "E547D55956F678EEEE5E92B2",
        "requesterNonce": "1f500e97a3f27292fcf2bce82d66ff8a",
        "encryptedRequestHash": "9FF1CCCFEF95C1A6268AB9CF90569AB007DD246C5B91906DE3CD63CA03F007786EC3C889F10859276E982B44F25CEB6D",
        "requesterSignature": "",
        "inData": [
            {
                "index": 0,
                "data": "Vkveu35IUaWfSlV6PXzjmNtKtBmm"
            }
        ]
    }
}`

type WorkOrderSubmit struct {
	Jsonrpc string `json:"jsonrpc"`
	Method  string `json:"method"`
	ID      int    `json:"id"`
	Params  struct {
		WorkOrderID             string `json:"workOrderId"`
		ResponseTimeoutMSecs    int    `json:"responseTimeoutMSecs"`
		PayloadFormat           string `json:"payloadFormat"`
		ResultURI               string `json:"resultUri"`
		NotifyURI               string `json:"notifyUri"`
		WorkerID                string `json:"workerId"`
		WorkloadID              string `json:"workloadId"`
		RequesterID             string `json:"requesterId"`
		WorkerEncryptionKey     string `json:"workerEncryptionKey"`
		DataEncryptionAlgorithm string `json:"dataEncryptionAlgorithm"`
		EncryptedSessionKey     string `json:"encryptedSessionKey"`
		SessionKeyIv            string `json:"sessionKeyIv"`
		RequesterNonce          string `json:"requesterNonce"`
		EncryptedRequestHash    string `json:"encryptedRequestHash"`
		RequesterSignature      string `json:"requesterSignature"`
		InData                  []struct {
			Index int    `json:"index"`
			Data  string `json:"data"`
		} `json:"inData"`
	} `json:"params"`
}

//----------------------------------------------------------
var workOrderSubmitResponseTest = `{
    "result": {
        "workOrderId": "9d44c6f7a310e2abdcfa23cef7a507658a68bbac8665b8162e53af187c2ca46f",
        "workloadId": "6563686f2d726573756c74",
        "workerId": "ad8ef7abd63076b74175d49e3db3087da1c6f46ff8912a87cb354c816a6ad26b",
        "requesterId": "e20e576e6835efa179fdddf677cae1111d94f620e1e4946ce2a2833003df9d8e",
        "workerNonce": "HtXfHfRmpJ4qBaVzbSUcOZjVR7I7TCgRbNCLq+suL5w=",
        "workerSignature": "MEQCID78N1Mcnu098NTCprxpIQ4s4P8lg+MJxHMBh7nNVer6AiAl7gGsa7lnFZKJE3ecNRfJIR1mF3uXB8u16smsQMjWoA==",
        "outData": [
            {
                "index": 0,
                "dataHash": "84EA068A1326A99D02AF62D878FD15A5F2AFA8CF7BAAFADD95DA31165E3B45F1",
                "data": "TGvhgl2l8Kn5TznI9aXbTYJ0ifnmN3EDWHJR5/s=",
                "encryptedDataEncryptionKey": "",
                "iv": ""
            }
        ],
        "extVerificationKey": "-----BEGIN PUBLIC KEY-----\nMFYwEAYHKoZIzj0CAQYFK4EEAAoDQgAE7zfP6KQmkaPi0PtOHVyKybpKc9m60WUx\nDXXcC+Y9mVHR86bjpNeoAw3lqpuuSMK3OmvJWqSUjEEgr3iaTwgCRg==\n-----END PUBLIC KEY-----\n",
        "extVerificationKeySignature": "MEQCIC3Rmw9g707yozu0+797mM2yqRv35x4ho5ox//JP893NAiB+JtrNDGX3j12OMLficV2UYYUBm89fbjkYdWkagUDx3Q=="
    },
    "id": 33,
    "jsonrpc": "2.0"
}`

type WorkOrderSubmitResponse struct {
	Result struct {
		WorkOrderID     string `json:"workOrderId"`
		WorkloadID      string `json:"workloadId"`
		WorkerID        string `json:"workerId"`
		RequesterID     string `json:"requesterId"`
		WorkerNonce     string `json:"workerNonce"`
		WorkerSignature string `json:"workerSignature"`
		OutData         []OutData `json:"outData"`
		ExtVerificationKey          string `json:"extVerificationKey"`
		ExtVerificationKeySignature string `json:"extVerificationKeySignature"`
	} `json:"result"`
	ID      int    `json:"id"`
	Jsonrpc string `json:"jsonrpc"`
}

type OutData struct {
	Index                      int    `json:"index"`
	DataHash                   string `json:"dataHash"`
	Data                       string `json:"data"`
	EncryptedDataEncryptionKey string `json:"encryptedDataEncryptionKey"`
	Iv                         string `json:"iv"`
}

//------------------------------------------------

var WorkOrderGetResultTest = `{
    "result": {
        "workOrderId": "9d44c6f7a310e2abdcfa23cef7a507658a68bbac8665b8162e53af187c2ca46f",
        "workloadId": "6563686f2d726573756c74",
        "workerId": "ad8ef7abd63076b74175d49e3db3087da1c6f46ff8912a87cb354c816a6ad26b",
        "requesterId": "e20e576e6835efa179fdddf677cae1111d94f620e1e4946ce2a2833003df9d8e",
        "workerNonce": "HtXfHfRmpJ4qBaVzbSUcOZjVR7I7TCgRbNCLq+suL5w=",
        "workerSignature": "MEQCID78N1Mcnu098NTCprxpIQ4s4P8lg+MJxHMBh7nNVer6AiAl7gGsa7lnFZKJE3ecNRfJIR1mF3uXB8u16smsQMjWoA==",
        "outData": [
            {
                "index": 0,
                "dataHash": "84EA068A1326A99D02AF62D878FD15A5F2AFA8CF7BAAFADD95DA31165E3B45F1",
                "data": "TGvhgl2l8Kn5TznI9aXbTYJ0ifnmN3EDWHJR5/s=",
                "encryptedDataEncryptionKey": "",
                "iv": ""
            }
        ],
        "extVerificationKey": "-----BEGIN PUBLIC KEY-----\nMFYwEAYHKoZIzj0CAQYFK4EEAAoDQgAE7zfP6KQmkaPi0PtOHVyKybpKc9m60WUx\nDXXcC+Y9mVHR86bjpNeoAw3lqpuuSMK3OmvJWqSUjEEgr3iaTwgCRg==\n-----END PUBLIC KEY-----\n",
        "extVerificationKeySignature": "MEQCIC3Rmw9g707yozu0+797mM2yqRv35x4ho5ox//JP893NAiB+JtrNDGX3j12OMLficV2UYYUBm89fbjkYdWkagUDx3Q=="
    },
    "id": 34,
    "jsonrpc": "2.0"
}`

type WorkOrderGetResult struct {
	Result struct {
		WorkOrderID     string `json:"workOrderId"`
		WorkloadID      string `json:"workloadId"`
		WorkerID        string `json:"workerId"`
		RequesterID     string `json:"requesterId"`
		WorkerNonce     string `json:"workerNonce"`
		WorkerSignature string `json:"workerSignature"`
		OutData         []struct {
			Index                      int    `json:"index"`
			DataHash                   string `json:"dataHash"`
			Data                       string `json:"data"`
			EncryptedDataEncryptionKey string `json:"encryptedDataEncryptionKey"`
			Iv                         string `json:"iv"`
		} `json:"outData"`
		ExtVerificationKey          string `json:"extVerificationKey"`
		ExtVerificationKeySignature string `json:"extVerificationKeySignature"`
	} `json:"result"`
	ID      int    `json:"id"`
	Jsonrpc string `json:"jsonrpc"`
}
