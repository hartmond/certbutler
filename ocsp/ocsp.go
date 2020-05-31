package ocsp

import (
	"bytes"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"

	"felix-hartmond.de/projects/certbutler/common"

	"golang.org/x/crypto/ocsp"
)

func GetOcspResponse(certfile string) (*ocsp.Response, error) {
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

	ocspResponse, err := ocsp.ParseResponse(ocspResponseRaw, issueCert)
	if err != nil {
		return nil, err
	}

	err = ioutil.WriteFile(certfile+".ocsp", ocspResponseRaw, os.FileMode(int(0600)))
	if err != nil {
		return nil, err
	}

	return ocspResponse, nil
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
