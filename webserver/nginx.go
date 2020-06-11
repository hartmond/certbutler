package webserver

import (
	"crypto/ecdsa"
	"fmt"

	"felix-hartmond.de/projects/certbutler/common"
)

type NginxInteraction struct {
	config  common.Config
	changes bool
}

func (server *NginxInteraction) GetRequirements() (bool, bool) {
	return true, false
}

func (server *NginxInteraction) SetCert(certs [][]byte, key *ecdsa.PrivateKey) error {
	err := common.SaveToPEMFile(server.config.CertFile, nil, certs)
	if err != nil {
		return err
	}
	err = common.SaveToPEMFile(server.config.KeyFile, key, nil)
	if err != nil {
		return err
	}

	server.changes = true
	return nil
}

func (server *NginxInteraction) SetOCSP([]byte) error {
	return fmt.Errorf("Nginx does not take prepared OCSP responses")
}

func (server *NginxInteraction) UpdateServer() error {
	// TODO reload server
	return nil
}
