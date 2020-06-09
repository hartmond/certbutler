package ocsp

import (
	"bytes"
	"io/ioutil"
	"log"
	"net/http"

	"felix-hartmond.de/projects/certbutler/common"

	"golang.org/x/crypto/ocsp"
)

func GetOcspResponse(certfile string) ([]byte, error) {
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

func PrintStatus(ocspResponse *ocsp.Response) {
	log.Println("ProducedAt: ", ocspResponse.ProducedAt)
	log.Println("ThisUpdate: ", ocspResponse.ThisUpdate)
	log.Println("NextUpdate: ", ocspResponse.NextUpdate)
	switch ocspResponse.Status {
	case ocsp.Good:
		log.Println("Status: Good")
	case ocsp.Revoked:
		log.Printf("Status: Revoked (At: %)", ocspResponse.RevokedAt)
	case ocsp.Unknown:
		log.Println("Status: Unknown")
	}
}

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
