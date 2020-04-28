package main

import (
	"fmt"
	"io/ioutil"
	"os"
	"golang.org/x/crypto/ocsp"
)

func main() {
	certfile := "example.com"

	ocspResponse, ocspResponseRaw, err := getOcspResponse(certfile)
	if err != nil {
		panic(err)
	}

	err = ioutil.WriteFile(certfile+".pem.ocsp", ocspResponseRaw, os.FileMode(int(0777)))
	if err != nil {
		panic(err)
	}

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
