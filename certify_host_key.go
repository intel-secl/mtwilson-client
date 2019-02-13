package mtwilson

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"path"
)

// Error is an error struct that contains error information thrown by the actual HVS
type Error struct {
	StatusCode int
	Message    string
}

type HostKey struct {
	client *Client
}

type RegisterKeyInfo struct {
	PublicKeyModulus       []byte `json:"public_key_modulus,omitempty"`
	TpmCertifyKey          []byte `json:"tpm_certify_key,omitempty"`
	TpmCertifyKeySignature []byte `json:"tpm_certify_key_signature,omitempty"`
	AikDerCertificate      []byte `json:"aik_der_certificate,omitempty"`
	NameDigest             []byte `json:"name_digest,omitempty"`
	TpmVersion             string `json:"tpm_version,omitempty"`
	OsType                 string `json:"operating_system,omitempty"`
}
type BindingKeyCert struct {
	BindingKeyCertificate []byte `json:"binding_key_der_certificate,omitempty"`
}
type SigningKeyCert struct {
	SigningKeyCertificate []byte `json:"signing_key_der_certificate,omitempty"`
}

func (e Error) Error() string {
	return fmt.Sprintf("hvs-client: failed (HTTP Status Code: %d)\nMessage: %s", e.StatusCode, e.Message)
}

// CertifyHostBindingKey sends a POST to /certify-host-binding-key to register binding key with HVS
func (k *HostKey) CertifyHostBindingKey(key *RegisterKeyInfo) (*BindingKeyCert, error) {
	var keyCert BindingKeyCert
	rsp, err := k.certifyHostKey(key, "/rpc/certify-host-binding-key", "binding")
	if err != nil {
       return nil, errors.New("error registering binding key with HVS. " + err.Error())
	}
	defer rsp.Body.Close()
	err = json.NewDecoder(rsp.Body).Decode(&keyCert)
	if err != nil {
		return nil, errors.New("error decoding binding key certificate. " + err.Error())
	}
	return &keyCert, nil
}

// CertifyHostSigningKey sends a POST to /certify-host-signing-key to register binding key with HVS
func (k *HostKey) CertifyHostSigningKey(key *RegisterKeyInfo) (*SigningKeyCert, error) {
	var keyCert SigningKeyCert

	rsp, err := k.certifyHostKey(key, "/rpc/certify-host-signing-key", "signing")
	if err != nil {
		return nil, errors.New("error registering signing key with HVS. " + err.Error())
	}
	defer rsp.Body.Close()
	err = json.NewDecoder(rsp.Body).Decode(&keyCert)
	if err != nil {
		return nil, errors.New("error decoding signing key certificate. " + err.Error())
	}
	return &keyCert, nil
}


func (k *HostKey) certifyHostKey(key *RegisterKeyInfo, endPoint string, keyUsage string) (*http.Response, error) {

	kiJSON, err := json.Marshal(key)
	if err != nil {
		return nil, fmt.Errorf("error marshalling %s key. ", keyUsage)
	}

	certifyKeyURL, err := url.Parse(k.client.BaseURL)
	if err != nil {
		return nil, errors.New("error parsing base url. " + err.Error())
	}

	certifyKeyURL.Path = path.Join(certifyKeyURL.Path, endPoint)

	req, err := http.NewRequest("POST", certifyKeyURL.String(), bytes.NewBuffer(kiJSON))
	if err != nil {
		return nil, errors.New(err.Error())
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Content-Type", "application/json")
	req.SetBasicAuth(k.client.Username, k.client.Password)

	rsp, err := k.client.dispatchRequest(req)

	if rsp.StatusCode != http.StatusOK {
		errMsgBytes, _ := ioutil.ReadAll(rsp.Body)
		return nil, &Error{StatusCode: rsp.StatusCode, Message: fmt.Sprintf("Failed to register host %s key with HVS . Error : %s", keyUsage, string(errMsgBytes))}
	}
	return rsp, nil

}
