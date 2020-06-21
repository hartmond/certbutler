package webserver

import (
	"crypto/ecdsa"
	"fmt"
	"os/exec"

	"felix-hartmond.de/projects/certbutler/common"
)

// NginxInteraction handles interaction with an nginx web server
type NginxInteraction struct {
	config  common.Config
	changes bool
}

// GetRequirements returns whether certificates and/or OCSP responses should be renewed for this web server type
func (server *NginxInteraction) GetRequirements() (bool, bool) {
	return true, false
}

// SetCert stores a new certificate on disk and stages a nginx reload
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

// SetOCSP always fails as nginx takes care of OCSP responses itself
func (server *NginxInteraction) SetOCSP([]byte) error {
	return fmt.Errorf("Nginx does not take prepared OCSP responses")
}

// UpdateServer triggers the nginx process to reload to load the new certificate
func (server *NginxInteraction) UpdateServer() error {
	//https://docs.nginx.com/nginx/admin-guide/basic-functionality/runtime-control/
	return exec.Command("nginx", "-s", "reload").Run()
}
