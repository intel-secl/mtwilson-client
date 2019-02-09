package mtwilson

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
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
		return nil, err
	}

	certifyKeyURL, err := url.Parse(k.client.BaseURL + "/rpc/certify-host-binding-key")
	if err != nil {
		return nil, errors.New("error parsing url")
	}

	req, err := http.NewRequest("POST", certifyKeyURL.String(), bytes.NewBuffer(kiJSON))
	if err != nil {
		return nil, err
	}

	req.Header.Set("Accept", "application/json")
	req.Header.Set("Content-Type", "application/json")
	req.SetBasicAuth(k.client.Username, k.client.Password)

	rsp, err := k.client.dispatchRequest(req)
	defer rsp.Body.Close()

	err = json.NewDecoder(rsp.Body).Decode(&keyCert)
	if err != nil {
		return nil, err
	}
	return &keyCert, nil
}

// CertifyHostSigningKey sends a POST to /certify-host-signing-key to register binding key with HVS
func (k *HostKey) CertifyHostSigningKey(key RegisterKeyInfo) (*SigningKeyCert, error) {
	var keyCert SigningKeyCert

	kiJSON, err := json.Marshal(key)
	if err != nil {
		return nil, err
	}

	certifyKeyURL, err := url.Parse(k.client.BaseURL + "/rpc/certify-host-signing-key")
	if err != nil {
		return nil, errors.New("error parsing url")
	}
	req, err := http.NewRequest("POST", certifyKeyURL.String(), bytes.NewBuffer(kiJSON))
	if err != nil {
		return nil, err
	}

	req.Header.Set("Accept", "application/json")
	req.Header.Set("Content-Type", "application/json")
	req.SetBasicAuth(k.client.Username, k.client.Password)

	rsp, err := k.client.dispatchRequest(req)
	defer rsp.Body.Close()

	err = json.NewDecoder(rsp.Body).Decode(&keyCert)
	if err != nil {
		return nil, err
	}
	return &keyCert, nil
}
