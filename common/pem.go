package common

import (
	"bufio"
	"bytes"
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"os"
	"strings"
)

const (
	pemTypeKey  = "EC PRIVATE KEY"
	pemTypeCert = "CERTIFICATE"
)

// SaveToPEMFile saves certiceates and key pem encoded to a file
func SaveToPEMFile(filename string, key *ecdsa.PrivateKey, certs [][]byte, note string) error {
	// if file already exists rotate the old file
	if _, err := os.Stat(filename); err == nil {
		name, extension := "", ""
		if offset := strings.LastIndex(filename, "."); offset == -1 {
			name = filename
		} else {
			name = filename[:offset]
			extension = filename[offset:]
		}
		for i := 0; ; i++ {
			nextFilename := fmt.Sprintf("%s-%d%s", name, i, extension)
			if _, err := os.Stat(nextFilename); err != nil {
				if err = os.Rename(filename, nextFilename); err != nil {
					return err
				}
				break
			}
		}
	}

	fileData, err := EncodePem(key, certs, note)
	if err != nil {
		return err
	}
	return ioutil.WriteFile(filename, fileData, 0600)
}

// EncodePem encodes certificates and key in PEM format
func EncodePem(key *ecdsa.PrivateKey, certs [][]byte, note string) ([]byte, error) {
	var buf bytes.Buffer

	if note != "" {
		buf.WriteString(note)
		buf.WriteString("\n")
	}

	for _, cert := range certs {
		err := pem.Encode(&buf, &pem.Block{
			Type:  pemTypeCert,
			Bytes: cert,
		})
		if err != nil {
			return nil, err
		}
	}

	if key != nil {
		keyBytes, err := x509.MarshalECPrivateKey(key)
		if err != nil {
			return nil, err
		}
		err = pem.Encode(&buf, &pem.Block{
			Type:  pemTypeKey,
			Bytes: keyBytes,
		})
		if err != nil {
			return nil, err
		}
	}

	return buf.Bytes(), nil
}

// LoadKeyFromPEMFile parses a key from a pem file. Skip specifies how many keys are skipped before the next one is parsed and returned.
func LoadKeyFromPEMFile(filename string, skip int) (*ecdsa.PrivateKey, error) {
	dataBytes, err := loadFromPem(filename, pemTypeKey, skip)
	if err != nil {
		return nil, err
	}
	return x509.ParseECPrivateKey(dataBytes)
}

// LoadCertFromPEMFile parses a certificate from a pem file. Skip specifies how many certificates are skipped before the next one is parsed and returned.
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

// FlattenStringSlice joins strings from a slice with commas for printing
func FlattenStringSlice(stringSlice []string) string {
	if len(stringSlice) == 0 {
		return ""
	}
	flattened := ""
	for _, element := range stringSlice {
		flattened = flattened + element + ","
	}
	flattened = flattened[:len(flattened)-1] // Remove trailing comma
	return flattened
}

// WriteCertToFile writes Certificates and Key to PEM Files
// When singleFile is true, cert and key are bothes stored in certFile, otherwise they are stored in two separate files
func WriteCertToFile(certs [][]byte, key *ecdsa.PrivateKey, certFile, keyFile string, singleFile bool) error {
	if singleFile {
		err := SaveToPEMFile(certFile, key, certs, "")
		if err != nil {
			return err
		}
	} else {
		err := SaveToPEMFile(certFile, nil, certs, "")
		if err != nil {
			return err
		}
		err = SaveToPEMFile(keyFile, key, nil, "")
		if err != nil {
			return err
		}
	}
	return nil
}
