package haproxy

import (
	"crypto/ecdsa"
	"fmt"

	"felix-hartmond.de/projects/certbutler/common"
	"golang.org/x/crypto/ocsp"
)

// SaveCert saves a Certificate, its chain and key to a pem file
func SaveCert(config common.Config, key *ecdsa.PrivateKey, certs [][]byte) error {
	return common.SaveToPEMFile(config.CertFile, key, certs)
}

// UpdateServer sends a certificate, its chain and key to a haproxy process
func UpdateServer(config common.Config, key *ecdsa.PrivateKey, certs [][]byte) error {
	return fmt.Errorf("not implemented")
}

// SaveOCSP saves a OCSP response for stapling in a file
func SaveOCSP(config common.Config, response *ocsp.Response) error {
	return fmt.Errorf("not implemented")
}

// UpdateOCSP send a OCSP reponse for stapling to a haproxy process
func UpdateOCSP(config common.Config, response *ocsp.Response) error {
	return fmt.Errorf("not implemented")
}

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
