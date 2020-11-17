package postprocessing

import (
	"bufio"
	"encoding/base64"
	"fmt"
	"io/ioutil"
	"net"

	log "github.com/sirupsen/logrus"

	"felix-hartmond.de/projects/certbutler/common"
)

// ProcessHaProxy sends the updated certificate and/or OCSP response to haproxy
func ProcessHaProxy(haConfig common.HaProxyConfiguration, filesConfig common.FilesConfiguration, updateResult common.UpdateResultData) error {
	if filesConfig.SingleFile == false {
		return fmt.Errorf("Updating haproxy aborted as certificate and key are stored in different files (option singleFile in configuration")
	}

	sendCommand := createSendCommandFunc(haConfig.HAProxySocket)

	if updateResult.Key != nil {
		// both new Certificte and new OCPS response
		log.Println("Updateing Certificate and OCSP response over haproxy socket")

		// abort potenitally running transaction
		result, err := sendCommand(fmt.Sprintf("abort ssl cert %s\n", filesConfig.CertFile))
		if err != nil {
			return err
		}
		if result != fmt.Sprintf("Transaction aborted for certificate %s!\n\n", filesConfig.CertFile) && result != "No ongoing transaction!\n\n" {
			return fmt.Errorf("Aborting old transaction failed: %s", result)
		}

		// add certificate to new transaction
		certBytes, err := common.EncodePem(updateResult.Key, updateResult.Certificates)
		if err != nil {
			return err
		}
		result, err = sendCommand(fmt.Sprintf("set ssl cert %s <<\n%s\n", filesConfig.CertFile, string(certBytes)))
		if err != nil {
			return err
		}
		if result != fmt.Sprintf("Transaction created for certificate %s!\n\n", filesConfig.CertFile) {
			return fmt.Errorf("Staging new Certificate in haproxy failed: %s", result)
		}

		if updateResult.OCSPResponse != nil {
			// add ocsp response to transaction
			result, err = sendCommand(fmt.Sprintf("set ssl cert %s.ocsp <<\n%s\n\n", filesConfig.CertFile, base64.StdEncoding.EncodeToString(updateResult.OCSPResponse)))
			if err != nil {
				return err
			}
			if result != fmt.Sprintf("Transaction updated for certificate %s!\n\n", filesConfig.CertFile) {
				return fmt.Errorf("Staging OCSP response for new certificate in haproxy failed: %s", result)
			}
		}

		// commit transaction
		result, err = sendCommand(fmt.Sprintf("commit ssl cert %s\n", filesConfig.CertFile))
		if err != nil {
			return err
		}
		if result != fmt.Sprintf("Committing %s.\nSuccess!\n\n", filesConfig.CertFile) {
			return fmt.Errorf("Staging OCSP response for new certificate in haproxy failed: %s", result)
		}

		return nil
	}

	if updateResult.OCSPResponse != nil {
		// only new OCSP response
		log.Println("Updateing OCSP response over haproxy socket")

		result, err := sendCommand(fmt.Sprintf("set ssl ocsp-response <<\n%s\n\n", base64.StdEncoding.EncodeToString(updateResult.OCSPResponse)))
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

func createSendCommandFunc(HAProxySocket string) func(string) (string, error) {
	return func(command string) (string, error) {
		conn, err := net.Dial("unix", HAProxySocket)
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
}
