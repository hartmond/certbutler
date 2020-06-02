package common

import (
	"bufio"
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
)

type Config struct {
	CertFile string

	DnsNames        []string
	MustStaple      bool
	AcmeDirectory   string
	AcmeAccountFile string
	RegsiterAcme    bool

	UpdateCert    bool
	UpdateOCSP    bool
	HAProxySocket string

	RunIntervalMinutes int

	RenewalDue int
}

const (
	pemTypeKey  = "EC PRIVATE KEY"
	pemTypeCert = "CERTIFICATE"
)

func SaveToPEMFile(filename string, key *ecdsa.PrivateKey, certs [][]byte) error {
	// TODO if file exists; maybe rename old file to archive it

	file, err := os.OpenFile(filename, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0600)
	if err != nil {
		return err
	}
	defer file.Close()

	if key != nil {
		keyBytes, err := x509.MarshalECPrivateKey(key)
		if err != nil {
			return err
		}
		err = pem.Encode(file, &pem.Block{
			Type:  pemTypeKey,
			Bytes: keyBytes,
		})
		if err != nil {
			return err
		}
	}

	for _, cert := range certs {
		err = pem.Encode(file, &pem.Block{
			Type:  pemTypeCert,
			Bytes: cert,
		})
		if err != nil {
			return err
		}
	}

	return nil
}

func LoadKeyFromPEMFile(filename string, skip int) (*ecdsa.PrivateKey, error) {
	dataBytes, err := loadFromPem(filename, pemTypeKey, skip)
	if err != nil {
		return nil, err
	}
	return x509.ParseECPrivateKey(dataBytes)
}

func LoadCertFromPEMFile(filename string, skip int) (*x509.Certificate, error) {
	dataBytes, err := loadFromPem(filename, pemTypeCert, skip)
	if err != nil {
		return nil, err
	}
	return x509.ParseCertificate(dataBytes)
}

func loadFromPem(filename, desc string, skip int) ([]byte, error) {
	pemFile, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	defer pemFile.Close()

	pemfileinfo, _ := pemFile.Stat()
	var size int64 = pemfileinfo.Size()
	pemBytes := make([]byte, size)
	buffer := bufio.NewReader(pemFile)
	_, err = buffer.Read(pemBytes)
	if err != nil {
		return nil, err
	}

	for {
		var pemBlock *pem.Block
		pemBlock, pemBytes = pem.Decode(pemBytes)
		if pemBlock == nil {
			return nil, fmt.Errorf("No pem block of type %s found after skipping %d blocks of same type", desc, skip)
		}
		if pemBlock.Type == desc {
			if skip > 0 {
				skip--
				continue
			}
			return pemBlock.Bytes, nil
		}
	}
}
