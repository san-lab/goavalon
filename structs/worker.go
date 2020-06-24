package structs


var workerLookupResponseTest =`{
"result": {
"totalCount": 1,
"lookupTag": "ad8ef7abd63076b74175d49e3db3087da1c6f46ff8912a87cb354c816a6ad26b",
"ids": [
"ad8ef7abd63076b74175d49e3db3087da1c6f46ff8912a87cb354c816a6ad26b"
]
},
"id": 31,
"jsonrpc": "2.0"
}`

type WorkerLookupResponsed struct {
	Result struct {
		TotalCount int      `json:"totalCount"`
		LookupTag  string   `json:"lookupTag"`
		Ids        []string `json:"ids"`
	} `json:"result"`
	ID      int    `json:"id"`
	Jsonrpc string `json:"jsonrpc"`
}

//------------------------------------

var workerRetrieveRequestTest = `{"jsonrpc": "2.0", "method": "WorkerRetrieve", "id": 2, "params": {"workerId": "2dc07db09d0ccd1a69a262f02b32fd31886b2f4cdf208c8cdedc450f14a91dda", "workOrderId": null}}`

type WorkerRetrieveRequest struct {
	Jsonrpc string `json:"jsonrpc"`
	Method  string `json:"method"`
	ID      int    `json:"id"`
	Params  struct {
		WorkerID    string      `json:"workerId"`
		WorkOrderID interface{} `json:"workOrderId"`
	} `json:"params"`
}

//--------------------------------------

var workerRetrieveResponseTest = `{
    "result": {
        "workerType": 1,
        "organizationId": "aabbcc1234ddeeff",
        "applicationTypeId": "11aa22bb33cc44dd",
        "details": {
            "workOrderSyncUri": "",
            "workOrderAsyncUri": "",
            "workOrderPullUri": "",
            "workOrderNotifyUri": "",
            "receiptInvocationUri": "",
            "workOrderInvocationAddress": "",
            "receiptInvocationAddress": "",
            "fromAddress": "",
            "hashingAlgorithm": "SHA-256",
            "signingAlgorithm": "SECP256K1",
            "keyEncryptionAlgorithm": "RSA-OAEP-3072",
            "dataEncryptionAlgorithm": "AES-GCM-256",
            "workOrderPayloadFormats": "JSON-RPC",
            "workerTypeData": {
                "verificationKey": "-----BEGIN PUBLIC KEY-----\nMFYwEAYHKoZIzj0CAQYFK4EEAAoDQgAEAaWC2DjQ9l88wmlhy8zXK8CpXDSCLjaM\nU6JHBb5eiJPQpvj41THtZuGd4hsPZf6lUzNgzJWPR1z4QQ2IwGANTg==\n-----END PUBLIC KEY-----\n",
                "extendedMeasurements": [
                    "F96B1426FEC20F217482D3C9C31FC7EA00000000000000000000000000000000",
                    "051DCF1DE45F01A40FA9621C1E1A77EB0176482D8FEF617BD47651AA48BFEE24"
                ],
                "proofDataType": "TEE-SGX-IAS",
                "proofData": "{\"verification_report\": \"{\\\"nonce\\\":\\\"FAFEF296CD72128182BD0488F6EEC61E\\\",\\\"id\\\":\\\"120397330191603157918718233616006689564\\\",\\\"timestamp\\\":\\\"2020-06-18T06:02:17.537245\\\",\\\"version\\\":3,\\\"epidPseudonym\\\":\\\"yxJPg4+PUC8X/OFD61UUOc/jxlmY3b3Bg4sApiPxIMUab8ulkN1wbtUGbeZMS4bMivuXu9LL9E8AHkx+P44Sux9nS+itVF8fVeLRAqK+Rt6fWnKemQrt5TXZivOVrHWeiqSGAK5oUl8isPlVWb6lEwpK1OLezqyCWgI6T8FOC7Q=\\\",\\\"isvEnclaveQuoteStatus\\\":\\\"GROUP_OUT_OF_DATE\\\",\\\"platformInfoBlob\\\":\\\"1502006504000700000F0F02040101070000000000000000000B00000B000000020000000000000B12B3302FE5ACBB7879F958E4002C43B13EE48967D7FA0FAB9821226E97BC261B2DB837548CAA0C54B38DB4C3DC549B74C6E2EEE394907D85208C58EB51354B06E7\\\",\\\"isvEnclaveQuoteBody\\\":\\\"AgABABILAAAKAAkAAAAAAPlrFCb+wg8hdILTycMfx+oAAAAAAAAAAAAAAAAAAAAAAxACBAECAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABwAAAAAAAAAHAAAAAAAAAAUdzx3kXwGkD6liHB4ad+sBdkgtj+9he9R2UapIv+4kAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABeb+jirqPytwep+IaASFSJbwGE0fa9OH57iOEbzCrQYAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAOeQAQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABN5lgM+pmWcudEBx7wYqOGheOX9MosjK/ULrDGE6MDn3KbmKdUy73iwwfiVj5GfYqWXpNFoXsqMuXvTwg7B/je\\\"}\", \"ias_report_signature\": \"MG/mQXLcgjeK+4CPI3ektUGtFOlRjD4hr/7oLwcXM45B2ow8mTHaW5a5Wwu7sVxX+LsTOJSiMLVqQKveZRtMchsbH0F+M0pkkryfy1gqqbxMtF4a54pHIX7sVtoG7gIW6MqwMDI9vYUCpX9ip6P69CODKMkV9gfuRxz+DX0dAR2r+uHWUMgo709o4j4hA8IZ7LongETFeP2xkhqQvTyUNkQ/LENLi8aFSjGc680+S3rf7LMthqRzyNwDeGN3JkTDmAitlCQqktjHhFvx9AVJZmDfzeZko4iEH803+xfcAQ2wXcQnKlKWlcBEqhZzy8rxCuH9sclRLtSksroyhyBJRA==\", \"ias_report_signing_certificate\": \"-----BEGIN CERTIFICATE-----\\nMIIEoTCCAwmgAwIBAgIJANEHdl0yo7CWMA0GCSqGSIb3DQEBCwUAMH4xCzAJBgNV\\nBAYTAlVTMQswCQYDVQQIDAJDQTEUMBIGA1UEBwwLU2FudGEgQ2xhcmExGjAYBgNV\\nBAoMEUludGVsIENvcnBvcmF0aW9uMTAwLgYDVQQDDCdJbnRlbCBTR1ggQXR0ZXN0\\nYXRpb24gUmVwb3J0IFNpZ25pbmcgQ0EwHhcNMTYxMTIyMDkzNjU4WhcNMjYxMTIw\\nMDkzNjU4WjB7MQswCQYDVQQGEwJVUzELMAkGA1UECAwCQ0ExFDASBgNVBAcMC1Nh\\nbnRhIENsYXJhMRowGAYDVQQKDBFJbnRlbCBDb3Jwb3JhdGlvbjEtMCsGA1UEAwwk\\nSW50ZWwgU0dYIEF0dGVzdGF0aW9uIFJlcG9ydCBTaWduaW5nMIIBIjANBgkqhkiG\\n9w0BAQEFAAOCAQ8AMIIBCgKCAQEAqXot4OZuphR8nudFrAFiaGxxkgma/Es/BA+t\\nbeCTUR106AL1ENcWA4FX3K+E9BBL0/7X5rj5nIgX/R/1ubhkKWw9gfqPG3KeAtId\\ncv/uTO1yXv50vqaPvE1CRChvzdS/ZEBqQ5oVvLTPZ3VEicQjlytKgN9cLnxbwtuv\\nLUK7eyRPfJW/ksddOzP8VBBniolYnRCD2jrMRZ8nBM2ZWYwnXnwYeOAHV+W9tOhA\\nImwRwKF/95yAsVwd21ryHMJBcGH70qLagZ7Ttyt++qO/6+KAXJuKwZqjRlEtSEz8\\ngZQeFfVYgcwSfo96oSMAzVr7V0L6HSDLRnpb6xxmbPdqNol4tQIDAQABo4GkMIGh\\nMB8GA1UdIwQYMBaAFHhDe3amfrzQr35CN+s1fDuHAVE8MA4GA1UdDwEB/wQEAwIG\\nwDAMBgNVHRMBAf8EAjAAMGAGA1UdHwRZMFcwVaBToFGGT2h0dHA6Ly90cnVzdGVk\\nc2VydmljZXMuaW50ZWwuY29tL2NvbnRlbnQvQ1JML1NHWC9BdHRlc3RhdGlvblJl\\ncG9ydFNpZ25pbmdDQS5jcmwwDQYJKoZIhvcNAQELBQADggGBAGcIthtcK9IVRz4r\\nRq+ZKE+7k50/OxUsmW8aavOzKb0iCx07YQ9rzi5nU73tME2yGRLzhSViFs/LpFa9\\nlpQL6JL1aQwmDR74TxYGBAIi5f4I5TJoCCEqRHz91kpG6Uvyn2tLmnIdJbPE4vYv\\nWLrtXXfFBSSPD4Afn7+3/XUggAlc7oCTizOfbbtOFlYA4g5KcYgS1J2ZAeMQqbUd\\nZseZCcaZZZn65tdqee8UXZlDvx0+NdO0LR+5pFy+juM0wWbu59MvzcmTXbjsi7HY\\n6zd53Yq5K244fwFHRQ8eOB0IWB+4PfM7FeAApZvlfqlKOlLcZL2uyVmzRkyR5yW7\\n2uo9mehX44CiPJ2fse9Y6eQtcfEhMPkmHXI01sN+KwPbpA39+xOsStjhP9N1Y1a2\\ntQAVo+yVgLgV2Hws73Fc0o3wC78qPEA+v2aRs/Be3ZFDgDyghc/1fgU+7C+P6kbq\\nd4poyb6IW8KCJbxfMJvkordNOgOUUxndPHEi/tb/U7uLjLOgPA==\\n-----END CERTIFICATE-----\\n-----BEGIN CERTIFICATE-----\\nMIIFSzCCA7OgAwIBAgIJANEHdl0yo7CUMA0GCSqGSIb3DQEBCwUAMH4xCzAJBgNV\\nBAYTAlVTMQswCQYDVQQIDAJDQTEUMBIGA1UEBwwLU2FudGEgQ2xhcmExGjAYBgNV\\nBAoMEUludGVsIENvcnBvcmF0aW9uMTAwLgYDVQQDDCdJbnRlbCBTR1ggQXR0ZXN0\\nYXRpb24gUmVwb3J0IFNpZ25pbmcgQ0EwIBcNMTYxMTE0MTUzNzMxWhgPMjA0OTEy\\nMzEyMzU5NTlaMH4xCzAJBgNVBAYTAlVTMQswCQYDVQQIDAJDQTEUMBIGA1UEBwwL\\nU2FudGEgQ2xhcmExGjAYBgNVBAoMEUludGVsIENvcnBvcmF0aW9uMTAwLgYDVQQD\\nDCdJbnRlbCBTR1ggQXR0ZXN0YXRpb24gUmVwb3J0IFNpZ25pbmcgQ0EwggGiMA0G\\nCSqGSIb3DQEBAQUAA4IBjwAwggGKAoIBgQCfPGR+tXc8u1EtJzLA10Feu1Wg+p7e\\nLmSRmeaCHbkQ1TF3Nwl3RmpqXkeGzNLd69QUnWovYyVSndEMyYc3sHecGgfinEeh\\nrgBJSEdsSJ9FpaFdesjsxqzGRa20PYdnnfWcCTvFoulpbFR4VBuXnnVLVzkUvlXT\\nL/TAnd8nIZk0zZkFJ7P5LtePvykkar7LcSQO85wtcQe0R1Raf/sQ6wYKaKmFgCGe\\nNpEJUmg4ktal4qgIAxk+QHUxQE42sxViN5mqglB0QJdUot/o9a/V/mMeH8KvOAiQ\\nbyinkNndn+Bgk5sSV5DFgF0DffVqmVMblt5p3jPtImzBIH0QQrXJq39AT8cRwP5H\\nafuVeLHcDsRp6hol4P+ZFIhu8mmbI1u0hH3W/0C2BuYXB5PC+5izFFh/nP0lc2Lf\\n6rELO9LZdnOhpL1ExFOq9H/B8tPQ84T3Sgb4nAifDabNt/zu6MmCGo5U8lwEFtGM\\nRoOaX4AS+909x00lYnmtwsDVWv9vBiJCXRsCAwEAAaOByTCBxjBgBgNVHR8EWTBX\\nMFWgU6BRhk9odHRwOi8vdHJ1c3RlZHNlcnZpY2VzLmludGVsLmNvbS9jb250ZW50\\nL0NSTC9TR1gvQXR0ZXN0YXRpb25SZXBvcnRTaWduaW5nQ0EuY3JsMB0GA1UdDgQW\\nBBR4Q3t2pn680K9+QjfrNXw7hwFRPDAfBgNVHSMEGDAWgBR4Q3t2pn680K9+Qjfr\\nNXw7hwFRPDAOBgNVHQ8BAf8EBAMCAQYwEgYDVR0TAQH/BAgwBgEB/wIBADANBgkq\\nhkiG9w0BAQsFAAOCAYEAeF8tYMXICvQqeXYQITkV2oLJsp6J4JAqJabHWxYJHGir\\nIEqucRiJSSx+HjIJEUVaj8E0QjEud6Y5lNmXlcjqRXaCPOqK0eGRz6hi+ripMtPZ\\nsFNaBwLQVV905SDjAzDzNIDnrcnXyB4gcDFCvwDFKKgLRjOB/WAqgscDUoGq5ZVi\\nzLUzTqiQPmULAQaB9c6Oti6snEFJiCQ67JLyW/E83/frzCmO5Ru6WjU4tmsmy8Ra\\nUd4APK0wZTGtfPXU7w+IBdG5Ez0kE1qzxGQaL4gINJ1zMyleDnbuS8UicjJijvqA\\n152Sq049ESDz+1rRGc2NVEqh1KaGXmtXvqxXcTB+Ljy5Bw2ke0v8iGngFBPqCTVB\\n3op5KBG3RjbF6RRSzwzuWfL7QErNC8WEy5yDVARzTA5+xmBc388v9Dm21HGfcC8O\\nDD+gT9sSpssq0ascmvH49MOgjt1yoysLtdCtJW/9FZpoOypaHx0R+mJTLwPXVMrv\\nDaVzWh5aiEx+idkSGMnX\\n-----END CERTIFICATE-----\\n\"}",
                "encryptionKey": "-----BEGIN PUBLIC KEY-----\nMIIBojANBgkqhkiG9w0BAQEFAAOCAY8AMIIBigKCAYEAwJM6Af9oeopBgDIeDwio\nQhpaRQ2goW0BKYexkuXk/TwRKi2TwciAzTgjImsaGWb0PvCUZfN05BmVOkRClXx7\nrPDifZ6xTiPHyer/qMSxbxKM4/TRVDTTrY8QHucCYYe4ypVWZS1ECPAzQnzykP+R\neR6G66zRzGUinEe87/8/97gSX1An4C9kGJ4/cu7Z+Dg24sSVvX/BJ8O7yIo15Rae\n75aEU7+r94Hmmw6Ygt4NXZaKOYNR52ROvn5LrJK6iDbicLCx95oFtwGVLko0NXp8\nf9NxDxn6PnXg4/cQ52ekcE3epZoee1DIe8ee5GUzliEdJEhsZ5m60wBaE822+B9o\nIRk2Ywe9TLztkCYmiIgIZnU2QCu2llx2iZzwATNtWTNEfvGfoEvH6lMqr1Vzj7c6\neKYAaTtoFRMAxM9TmHihUVMAtij4xeRfNfG5OPGoHgM1VHd8RWAPH0PkQGSBqUze\niLQsFEjxSRxbFH3/5xMUPiRHMbEHnLuCJ/NDCHX4VDqPAgMBAAE=\n-----END PUBLIC KEY-----\n",
                "encryptionKeySignature": "3045022100CC431B5EC4425CF0B6A567FA81294B44BC85C939AC4BF864E6E88067AC01D361022025E5DD0589AB280C54322D3CA9B8F60C47233E309D652A8983D52FF00A9DE905"
            }
        },
        "status": 1
    },
    "id": 32,
    "jsonrpc": "2.0"
}`

type WorkerRetrieveResponse struct {
	Result struct {
		WorkerType        int    `json:"workerType"`
		OrganizationID    string `json:"organizationId"`
		ApplicationTypeID string `json:"applicationTypeId"`
		Details           struct {
			WorkOrderSyncURI           string `json:"workOrderSyncUri"`
			WorkOrderAsyncURI          string `json:"workOrderAsyncUri"`
			WorkOrderPullURI           string `json:"workOrderPullUri"`
			WorkOrderNotifyURI         string `json:"workOrderNotifyUri"`
			ReceiptInvocationURI       string `json:"receiptInvocationUri"`
			WorkOrderInvocationAddress string `json:"workOrderInvocationAddress"`
			ReceiptInvocationAddress   string `json:"receiptInvocationAddress"`
			FromAddress                string `json:"fromAddress"`
			HashingAlgorithm           string `json:"hashingAlgorithm"`
			SigningAlgorithm           string `json:"signingAlgorithm"`
			KeyEncryptionAlgorithm     string `json:"keyEncryptionAlgorithm"`
			DataEncryptionAlgorithm    string `json:"dataEncryptionAlgorithm"`
			WorkOrderPayloadFormats    string `json:"workOrderPayloadFormats"`
			WorkerTypeData             struct {
				VerificationKey        string   `json:"verificationKey"`
				ExtendedMeasurements   []string `json:"extendedMeasurements"`
				ProofDataType          string   `json:"proofDataType"`
				ProofData              string   `json:"proofData"`
				EncryptionKey          string   `json:"encryptionKey"`
				EncryptionKeySignature string   `json:"encryptionKeySignature"`
			} `json:"workerTypeData"`
		} `json:"details"`
		Status int `json:"status"`
	} `json:"result"`
	ID      int    `json:"id"`
	Jsonrpc string `json:"jsonrpc"`
}