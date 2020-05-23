package ocsp

import (
	"bytes"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"net/http"

	"golang.org/x/crypto/ocsp"
)

func GetOcspResponse(certfile string) (*ocsp.Response, []byte, error) {
	cert, err := loadPemCertificate(certfile + ".pem")
	if err != nil {
		return nil, nil, err
	}

	issueCert, err := loadPemCertificate(certfile + ".pem.issue")
	if err != nil {
		return nil, nil, err
	}

	ocspRequest, err := ocsp.CreateRequest(cert, issueCert, nil)
	if err != nil {
		return nil, nil, err
	}

	httpResponse, err := http.Post(cert.OCSPServer[0], "application/ocsp-request", bytes.NewBuffer(ocspRequest))
	if err != nil {
		return nil, nil, err
	}

	defer httpResponse.Body.Close()

	ocspResponseRaw, err := ioutil.ReadAll(httpResponse.Body)
	if err != nil {
		return nil, nil, err
	}

	ocspResponse, err := ocsp.ParseResponse(ocspResponseRaw, issueCert)
	if err != nil {
		return nil, nil, err
	}

	return ocspResponse, ocspResponseRaw, nil
}

func PrintStatus(ocspResponse *ocsp.Response) {
	fmt.Println("ProducedAt: ", ocspResponse.ProducedAt)
	fmt.Println("ThisUpdate: ", ocspResponse.ThisUpdate)
	fmt.Println("NextUpdate: ", ocspResponse.NextUpdate)
	switch ocspResponse.Status {
	case ocsp.Good:
		fmt.Println("Status: Good")
	case ocsp.Revoked:
		fmt.Printf("Status: Revoked (At: %)", ocspResponse.RevokedAt)
	case ocsp.Unknown:
		fmt.Println("Status: Unknown")
	}
}

func loadPemCertificate(filename string) (*x509.Certificate, error) {
	certBytes, err := ioutil.ReadFile(filename)
	if err != nil {
		return nil, err
	}
	pemBlock, _ := pem.Decode(certBytes)
	return x509.ParseCertificate(pemBlock.Bytes)
}
