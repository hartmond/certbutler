package webserver

import (
	"bufio"
	"crypto/ecdsa"
	"encoding/base64"
	"fmt"
	"io/ioutil"
	"net"
	"os"

	log "github.com/sirupsen/logrus"

	"felix-hartmond.de/projects/certbutler/common"
)

// HaProxyInteraction handles interaction with an haproxy web server
type HaProxyInteraction struct {
	config      common.Config
	stagedCerts [][]byte
	stagedKey   *ecdsa.PrivateKey
	stagedOCSP  []byte
}

// GetRequirements returns whether certificates and/or OCSP responses should be renewed for this web server type
func (server *HaProxyInteraction) GetRequirements() (bool, bool) {
	return true, true
}

// SetCert stores a new certificate on disk and stages it for transmitting to haproxy
func (server *HaProxyInteraction) SetCert(certs [][]byte, key *ecdsa.PrivateKey) error {
	server.stagedCerts = certs
	server.stagedKey = key
	return common.SaveToPEMFile(server.config.CertFile, server.stagedKey, server.stagedCerts)
}

// SetOCSP stores a new OCSP response on disk and stages it for transmitting to haproxy
func (server *HaProxyInteraction) SetOCSP(response []byte) error {
	server.stagedOCSP = response
	return ioutil.WriteFile(server.config.CertFile+".ocsp", server.stagedOCSP, os.FileMode(int(0600)))
}

// UpdateServer sends the staged certificate and/or OCSP response to haproxy
func (server *HaProxyInteraction) UpdateServer() error {
	if server.stagedKey != nil {
		// both new Certificte and new OCPS response
		log.Println("Updateing Certificate and OCSP response over haproxy socket")

		// abort potenitally running transaction
		result, err := server.sendCommand(fmt.Sprintf("abort ssl cert %s\n", server.config.CertFile))
		if err != nil {
			return err
		}
		if result != fmt.Sprintf("Transaction aborted for certificate %s!\n\n", server.config.CertFile) && result != "No ongoing transaction!\n\n" {
			return fmt.Errorf("Aborting old transaction failed: %s", result)
		}

		// add certificate to new transaction
		certBytes, err := common.EncodePem(server.stagedKey, server.stagedCerts)
		if err != nil {
			return err
		}
		result, err = server.sendCommand(fmt.Sprintf("set ssl cert %s <<\n%s\n", server.config.CertFile, string(certBytes)))
		if err != nil {
			return err
		}
		if result != fmt.Sprintf("Transaction created for certificate %s!\n\n", server.config.CertFile) {
			return fmt.Errorf("Staging new Certificate in haproxy failed: %s", result)
		}

		// add ocsp response to transaction
		result, err = server.sendCommand(fmt.Sprintf("set ssl cert %s.ocsp <<\n%s\n\n", server.config.CertFile, base64.StdEncoding.EncodeToString(server.stagedOCSP)))
		if err != nil {
			return err
		}
		if result != fmt.Sprintf("Transaction updated for certificate %s!\n\n", server.config.CertFile) {
			return fmt.Errorf("Staging OCSP response for new certificate in haproxy failed: %s", result)
		}

		// commit transaction
		result, err = server.sendCommand(fmt.Sprintf("commit ssl cert %s\n", server.config.CertFile))
		if err != nil {
			return err
		}
		if result != fmt.Sprintf("Committing %s.\nSuccess!\n\n", server.config.CertFile) {
			return fmt.Errorf("Staging OCSP response for new certificate in haproxy failed: %s", result)
		}

		return nil
	}

	if server.stagedOCSP != nil {
		// only new OCSP response
		log.Println("Updateing OCSP response over haproxy socket")

		result, err := server.sendCommand(fmt.Sprintf("set ssl ocsp-response <<\n%s\n\n", base64.StdEncoding.EncodeToString(server.stagedOCSP)))
		if err != nil {
			return err
		}
		if string(result) != "OCSP Response updated!\n\n" {
			return fmt.Errorf("OCSP update over haproxy socker failed: %s", result)
		}

		return nil
	}

	log.Println("UpdateServer for haproxy called but no changes to update")
	return nil
}

func (server *HaProxyInteraction) sendCommand(command string) (string, error) {
	conn, err := net.Dial("unix", server.config.HAProxySocket)
	if err != nil {
		return "", err
	}
	defer conn.Close()

	fmt.Fprintf(conn, command)

	result, err := ioutil.ReadAll(bufio.NewReader(conn))
	if err != nil {
		return "", err
	}
	return string(result), err
}
