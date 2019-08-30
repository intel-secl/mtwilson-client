/*
 * Copyright (C) 2019 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package mtwilson

import (
	"crypto/tls"
	commonTls "intel/isecl/lib/common/tls"
	"net/http"
)

// A Client is defines parameters to connect and authenticate with HVS
type Client struct {
	// BaseURL specifies the URL base for the HVS, for example https://hvs.server/v1
	BaseURL string
	// Username used to authenticate with the HVS.
	Username string
	// Password to supply for the Username
	Password string
	// CertSha384 is a pointer to a 48 byte array that specifies the fingerprint of the immediate TLS certificate to trust.
	// If the value is a non nil pointer to a 48 byte array, custom TLS verification will be used, where any valid chain of X509 certificates
	// with a self signed CA at the root will be accepted as long as the Host Certificates Fingerprint matches what is provided here
	// If the value is a nil pointer, then system standard TLS verification will be used.
	CertSha384 *[48]byte
	// A reference to the underlying http Client.
	// If the value is nil, a default client will be created and used.
	HTTPClient *http.Client
}

func (c *Client) httpClient() *http.Client {
	if c.HTTPClient == nil {
		// init http client
		tlsConfig := tls.Config{}
		if c.CertSha384 != nil {
			// set explicit verification
			tlsConfig.InsecureSkipVerify = true
			tlsConfig.VerifyPeerCertificate = commonTls.VerifyCertBySha384(*c.CertSha384)
		}
		transport := http.Transport{
			TLSClientConfig: &tlsConfig,
		}
		c.HTTPClient = &http.Client{Transport: &transport}
	}
	return c.HTTPClient
}

// Keys returns a sub client that operates on hvs /keys endpoints, such as creating a new key
func (c *Client) HostKey() *HostKey {
	return &HostKey{client: c}
}

func (c *Client) dispatchRequest(req *http.Request) (*http.Response, error) {
	rsp, err := c.httpClient().Do(req)
	if err != nil {
		return nil, err
	}
	return rsp, err
}
