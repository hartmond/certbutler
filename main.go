package main

import (
	"io/ioutil"
	"os"

	"felix-hartmond.de/projects/certbutler/acme"
	"felix-hartmond.de/projects/certbutler/ocsp"
)

const (
	accountFile       = "acmeKey.pem"
	certFileBase      = "example.com" // cert will be safed as cerFileBase.pem; chain as certFileBase.pem.issue
	acmeDirectory     = "https://acme-staging-v02.api.letsencrypt.org/directory"
	regsiterIfMissing = true
)

func main() {
	dnsNames := []string{"example.com", "*.example.com"}
	err := acme.RequestCertificate(dnsNames, accountFile, certFileBase, acmeDirectory, regsiterIfMissing)
	if err != nil {
		panic(err)
	}
	//ocspTest()
}

func ocspTest() {
	certfile := "example.com"

	ocspResponse, ocspResponseRaw, err := ocsp.GetOcspResponse(certfile)
	if err != nil {
		panic(err)
	}

	err = ioutil.WriteFile(certfile+".pem.ocsp", ocspResponseRaw, os.FileMode(int(0777)))
	if err != nil {
		panic(err)
	}

	ocsp.PrintStatus(ocspResponse)
}
