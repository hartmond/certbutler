package main

import (
	"io/ioutil"
	"os"

	"felix-hartmond.de/projects/certbutler/acme"
	"felix-hartmond.de/projects/certbutler/ocsp"
)

func main() {
	acme.Test()
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
