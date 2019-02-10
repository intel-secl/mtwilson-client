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
	PublicKeyModulus       string `json:"public_key_modulus,omitempty"`
	TpmCertifyKey          string `json:"tpm_certify_key,omitempty"`
	TpmCertifyKeySignature string `json:"tpm_certify_key_signature,omitempty"`
	AikDerCertificate      []byte `json:"aik_der_certificate,omitempty"`
	NameDigest             string `json:"name_digest,omitempty"`
	TpmVersion             string `json:"tpm_version,omitempty"`
	OsType                 string `json:"operating_system,omitempty"`
}
type BindingKeyCert struct {
	BindingKeyCertificate string `json:"binding_key_der_certificate,omitempty"`
}
type SigningKeyCert struct {
	SigningKeyCertificate string `json:"signing_key_der_certificate,omitempty"`
}

func (e Error) Error() string {
	return fmt.Sprintf("hvs-client: failed (HTTP Status Code: %d)\nMessage: %s", e.StatusCode, e.Message)
}

// CertifyHostBindingKey sends a POST to /certify-host-binding-key to register binding key with HVS
func (k *HostKey) CertifyHostBindingKey(key RegisterKeyInfo) (*BindingKeyCert, error) {
	var keyCert BindingKeyCert

	kiJSON, err := json.Marshal(key)
	if err != nil {
		return nil, errors.New("error marshalling binding key ")
	}
	certifyKeyURL, err := url.Parse(k.client.BaseURL)
	if err != nil {
		return nil, errors.New("error parsing base url. " + err.Error())
	}
	
	certifyKeyURL.Path = path.Join(certifyKeyURL.Path,"/rpc/certify-host-binding-key")
	   
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
		return nil, &Error{StatusCode: rsp.StatusCode, Message: fmt.Sprintf("Failed to register host binding key with HVS. Error : %s", string(errMsgBytes))}
	}

	defer rsp.Body.Close()
	err = json.NewDecoder(rsp.Body).Decode(&keyCert)
	if err != nil {
		return nil, errors.New("error decoding binding key certificate. " + err.Error())
	}
	return &keyCert, nil
}

// CertifyHostSigningKey sends a POST to /certify-host-signing-key to register binding key with HVS
func (k *HostKey) CertifyHostSigningKey(key RegisterKeyInfo) (*SigningKeyCert, error) {
	var keyCert SigningKeyCert

	kiJSON, err := json.Marshal(key)
	if err != nil {
		return nil, errors.New("error marshalling signing key. ")
	}
	
	certifyKeyURL, err := url.Parse(k.client.BaseURL)
	if err != nil {
		return nil, errors.New("error parsing base url. " + err.Error())
	}
	
	certifyKeyURL.Path = path.Join(certifyKeyURL.Path,"/rpc/certify-host-signing-key")
	fmt.Println(certifyKeyURL.String())
	
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
		return nil, &Error{StatusCode: rsp.StatusCode, Message: fmt.Sprintf("Failed to register host signing key with HVS . Error : %s", string(errMsgBytes))}
	}
	defer rsp.Body.Close()

	err = json.NewDecoder(rsp.Body).Decode(&keyCert)
	if err != nil {
		return nil, errors.New("error decoding signing key certificate. " + err.Error())
	}
	return &keyCert, nil
}
