package mtwilson

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
)

type Keys struct {
	client *Client
}

type RegisterKeyInfo struct {
	PublicKeyModulus       string `json:"public_key_modulus,omitempty"`
	TpmCertifyKey          string `json:"tpm_certify_key,omitempty"`
	TpmCertifyKeySignature string `json:"tpm_certify_key_signature,omitempty"`
	AikDerCertificate      []byte `json:"aik_der_certificate,omitempty"`
	NameDigest             string `json:"name_digest,omitempty"`
	TpmVersion             string `json:"tpm_version,omitempty"`
	OsType                 string `json:"operating_system,omitempty"`
	BindingKeyCertificate  string `json:"binding_key_der_certificate,omitempty"`
	SigningKeyCertificate  string `json:"signing_key_der_certificate,omitempty"`
}

func (e Error) Error() string {
	return fmt.Sprintf("hvs-client: failed (HTTP Status Code: %d)\nMessage: %s", e.StatusCode, e.Message)
}

// Error is a error struct that contains error information thrown by the actual HVS
type Error struct {
	StatusCode int
	Message    string
}

// Create sends a POST to /keys to create a new Key with the specified parameters
func (k *Keys) Register(key RegisterKeyInfo, keyUrl string) (*RegisterKeyInfo, error) {
	// marshal KeyInfo
	kiJSON, err := json.Marshal(&key)
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequest("POST", keyUrl, bytes.NewBuffer(kiJSON))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Content-Type", "application/json")
	req.SetBasicAuth(k.client.Username, k.client.Password)

	rsp, err := k.client.dispatchRequest(req)
	defer rsp.Body.Close()

	var kiOut RegisterKeyInfo
	err = json.NewDecoder(rsp.Body).Decode(&kiOut)
	if err != nil {
		return nil, err
	}
	return &kiOut, nil
}
