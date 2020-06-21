package ocsp

import (
	"bytes"
	"io/ioutil"
	"net/http"
	"time"

	log "github.com/sirupsen/logrus"

	"felix-hartmond.de/projects/certbutler/common"

	"golang.org/x/crypto/ocsp"
)

// GetOCSPResponse gathers a new OCSP response for stapling
func GetOCSPResponse(certfile string) ([]byte, error) {
	log.Println("Requesting new OCSP response")
	cert, err := common.LoadCertFromPEMFile(certfile, 0)
	if err != nil {
		return nil, err
	}

	issueCert, err := common.LoadCertFromPEMFile(certfile, 1)
	if err != nil {
		return nil, err
	}

	ocspRequest, err := ocsp.CreateRequest(cert, issueCert, nil)
	if err != nil {
		return nil, err
	}

	httpResponse, err := http.Post(cert.OCSPServer[0], "application/ocsp-request", bytes.NewBuffer(ocspRequest))
	if err != nil {
		return nil, err
	}

	defer httpResponse.Body.Close()

	ocspResponseRaw, err := ioutil.ReadAll(httpResponse.Body)
	if err != nil {
		return nil, err
	}

	return ocspResponseRaw, nil
}

// LoadFromFile loads and parsesn an OCSP Response from a file
func LoadFromFile(certfile string) (*ocsp.Response, error) {
	rawOCSPBytes, err := ioutil.ReadFile(certfile + ".ocsp")
	if err != nil {
		return nil, err
	}

	issueCert, err := common.LoadCertFromPEMFile(certfile, 1)
	if err != nil {
		return nil, err
	}

	return ocsp.ParseResponse(rawOCSPBytes, issueCert)
}

// CheckOCSPRenew checks if a prepared OCSP response exists and if it is still longer valid than renewaldueocsp from config
func CheckOCSPRenew(config common.Config) bool {
	ocsp, err := LoadFromFile(config.CertFile)
	if err != nil {
		// ocsp missing or not valid => renew ocsp
		return true
	}

	if remainingValidity := time.Until(ocsp.NextUpdate); remainingValidity < time.Duration(config.RenewalDueOCSP*24)*time.Hour {
		// ocsp expires soon (in 3 days) => renew ocsp
		return true
	}

	return false
}
