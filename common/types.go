package common

import "crypto/ecdsa"

// Config is the struct holding all configuration for a certificate. The config file is parsed into this struct.
type Config struct {
	Timing      TimingConfiguration
	Certificate CertificateConfiguration
	Files       FilesConfiguration
	HaProxy     HaProxyConfiguration
	Nginx       NginxConfiguration
	DeployHook  DeployHookConfiguration
}

// TimingConfiguration stores the values defining scheduling and due dates
type TimingConfiguration struct {
	RunIntervalMinutes int
	RenewalDueCert     int // remaining valid days of the certitifcate before renew; set to 0 to disable Certificate refresh
	RenewalDueOCSP     int // remaining valid days of the OCSP response before renew; set to 0 to disable OCSP refresh
}

// CertificateConfiguration stores Certificate content ACME account data
type CertificateConfiguration struct {
	DNSNames         []string
	EllipticCurve    string
	MustStaple       bool
	AcmeDirectory    string
	AcmeAccountFile  string
	RegisterAcme     bool
	AcceptAcmeTOS    bool
	AcmeMailContacts []string
}

// FilesConfiguration stores how received content to files
type FilesConfiguration struct {
	SingleFile bool   // store cert and key CertFile (for e.g. haproxy)
	CertFile   string // store cert and key in two files (for e.g. nginx)
	KeyFile    string // store cert and key in two files (for e.g. nginx)
}

// HaProxyConfiguration stores whether and how certbutler interacts with haproxy
type HaProxyConfiguration struct {
	HAProxySocket string // leave empty to disable haproxy interaction
}

// NginxConfiguration stores whether and how certbutler interacts with nginx
type NginxConfiguration struct {
	ReloadNginx bool // set false und leave unset to disable nginx reload
}

// DeployHookConfiguration stores whether and which deployhook is run by certbutler
type DeployHookConfiguration struct {
	Executable string // Leave empyty to disable deploy hook execution
}

// UpdateResultData holds the received results for usage of post-processors
type UpdateResultData struct {
	Certificates [][]byte
	Key          *ecdsa.PrivateKey
	OCSPResponse []byte
}
