package nginx

import (
	"crypto/ecdsa"
	"fmt"

	"felix-hartmond.de/projects/certbutler/common"
)

// SaveCert saves a Certificate, its chain and key to pem files
func SaveCert(config common.Config, key *ecdsa.PrivateKey, certs [][]byte) error {
	err := common.SaveToPEMFile(config.CertFile, nil, certs[:1])
	if err != nil {
		return err
	}
	err = common.SaveToPEMFile(config.CertFile+"_chain", nil, certs[1:])
	if err != nil {
		return err
	}
	err = common.SaveToPEMFile(config.CertFile+"_key", key, nil)
	if err != nil {
		return err
	}
	return nil
}

// ReloadServer pokes nginx to reload its certificates
func ReloadServer(config common.Config) error {
	return fmt.Errorf("not implemented") // TODO
}
