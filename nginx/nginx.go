package nginx

import (
	"crypto/ecdsa"
	"fmt"

	"felix-hartmond.de/projects/certbutler/common"
)

type NginxInteraction struct {
	config  common.Config
	changes bool
}

func New(config common.Config) common.WebServerInteraction {
	return &NginxInteraction{
		config:  config,
		changes: false,
	}
}

func (server *NginxInteraction) GetRequirements() (bool, bool) {
	return true, false
}

func (server *NginxInteraction) SetCert(certs [][]byte, key *ecdsa.PrivateKey) error {
	err := common.SaveToPEMFile(server.config.CertFile, nil, certs[:1])
	if err != nil {
		return err
	}
	err = common.SaveToPEMFile(server.config.CertFile+"_chain", nil, certs[1:])
	if err != nil {
		return err
	}
	err = common.SaveToPEMFile(server.config.CertFile+"_key", key, nil)
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
	if server.changes {
		// TODO reload server
	}
	return nil
}
