package haproxy

import (
	"crypto/ecdsa"
	"io/ioutil"
	"os"

	"felix-hartmond.de/projects/certbutler/common"
)

type HaProxyInteraction struct {
	config      common.Config
	stagedCerts [][]byte
	stagedKey   *ecdsa.PrivateKey
	stagedOCSP  []byte
}

func New(config common.Config) common.WebServerInteraction {
	return &HaProxyInteraction{
		config: config,
	}
}

func (server *HaProxyInteraction) GetRequirements() (bool, bool) {
	return true, true
}

func (server *HaProxyInteraction) SetCert(certs [][]byte, key *ecdsa.PrivateKey) error {
	server.stagedCerts = certs
	server.stagedKey = key
	return common.SaveToPEMFile(server.config.CertFile, server.stagedKey, server.stagedCerts)
}

func (server *HaProxyInteraction) SetOCSP(response []byte) error {
	server.stagedOCSP = response
	return ioutil.WriteFile(server.config.CertFile+".ocsp", server.stagedOCSP, os.FileMode(int(0600)))
}

func (server *HaProxyInteraction) UpdateServer() error {

	// TODO update haproxy over socket
	return nil
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
