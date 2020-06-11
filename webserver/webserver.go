package webserver

import (
	"crypto/ecdsa"
	"log"

	"felix-hartmond.de/projects/certbutler/common"
)

// Interaction defines the interface for webserver modes
type Interaction interface {
	GetRequirements() (bool, bool)
	SetCert([][]byte, *ecdsa.PrivateKey) error
	SetOCSP([]byte) error
	UpdateServer() error
}

// New returns an Interaction object based on webserver mode in the configuration
func New(config common.Config) Interaction {
	if config.Mode == "haproxy" {
		return &HaProxyInteraction{
			config: config,
		}
	} else if config.Mode == "nginx" {
		return &NginxInteraction{
			config:  config,
			changes: false,
		}
	}
	log.Fatalf("Web server type %s not supported", config.Mode)
	return nil
}
