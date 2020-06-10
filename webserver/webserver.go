package webserver

import (
	"crypto/ecdsa"
	"log"

	"felix-hartmond.de/projects/certbutler/common"
)

type WebServerInteraction interface {
	GetRequirements() (bool, bool)
	SetCert([][]byte, *ecdsa.PrivateKey) error
	SetOCSP([]byte) error
	UpdateServer() error
}

func New(config common.Config) WebServerInteraction {
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
