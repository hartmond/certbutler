package haproxy

import (
	"crypto/ecdsa"
	"crypto/x509"

	"golang.org/x/crypto/ocsp"
)

// UpdateHAProxy provides a running proxy process with updated cert/key and ocsp respone. If element is nil it will not be updated.
func UpdateHAProxy(proxySocket string, key *ecdsa.PrivateKey, cert *x509.Certificate, ocsp *ocsp.Response) error {
	// TODO implement
	/*
		Notes:
		- haproxy socket (unix socket) interaction with net.Dial("unix", proxySocket)
		- socket commands:
			- show tls-keys [id|*]: show tls keys references or dump tls ticket keys when id specified
			- set ssl tls-key [id|keyfile] <tlskey>: set the next TLS key for the <id> or <keyfile> listener to <tlskey>
			- set ssl cert <certfile> <payload> : replace a certificate file
			- commit ssl cert <certfile> : commit a certificate file
			- abort ssl cert <certfile> : abort a transaction for a certificate file
	*/

	return nil
}
