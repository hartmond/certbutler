package acme

import (
	"bufio"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"fmt"
	"log"
	"os"

	"crypto/x509"
	"encoding/pem"

	"golang.org/x/crypto/acme"
)

const (
	acmeKeyFile = "acmeKey.pem"
	register    = false
)

var (
	dnsNames = []string{}
)

func Test() {
	ctx := context.Background()
	_ = ctx

	var client *acme.Client

	if register {
		// == REGISTER ==
		akey, err := createKeyFile(acmeKeyFile)
		if err != nil {
			panic(err)
		}

		client = &acme.Client{Key: akey, DirectoryURL: "https://acme-staging-v02.api.letsencrypt.org/directory"}

		_, err = client.Register(ctx, &acme.Account{}, acme.AcceptTOS)
		if err != nil {
			panic(err)
		}

	} else {
		// == LOGIN ==
		akey, err := loadKeyFile(acmeKeyFile)
		if err != nil {
			panic(err)
		}

		client = &acme.Client{Key: akey, DirectoryURL: "https://acme-staging-v02.api.letsencrypt.org/directory"}

		client.GetReg(ctx, "")
	}

	order, err := client.AuthorizeOrder(ctx, acme.DomainIDs(dnsNames...))
	if err != nil {
		panic(err)
	}

	for _, authURL := range order.AuthzURLs {
		authz, err := client.GetAuthorization(ctx, authURL)
		if err != nil {
			panic(err)
		}

		if authz.Status == acme.StatusValid {
			// Already authorized.
			continue
		}

		var chal *acme.Challenge
		for _, c := range authz.Challenges {
			if c.Type == "dns-01" {
				chal = c
				break
			}
		}
		if chal == nil {
			log.Fatalf("no dns-01 challenge for %q", authURL)
		}

		val, err := client.DNS01ChallengeRecord(chal.Token)
		if err != nil {
			log.Fatalf("dns-01 token for %q: %v", authz.Identifier, err)
		}

		fmt.Println("=> ", authz.Identifier, val)

		addDNSToken(val)

		if _, err := client.Accept(ctx, chal); err != nil {
			log.Fatalf("dns-01 accept for %q: %v", authz.Identifier, err)
		}
	}

	for _, authURL := range order.AuthzURLs {
		if _, err := client.WaitAuthorization(ctx, authURL); err != nil {
			log.Fatalf("authorization for %q failed: %v", authURL, err)
		}
	}

	clearDNSTokens()

	/*
		// All authorizations are granted. Request the certificate.
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			panic(err)
		}

		req := &x509.CertificateRequest{
			DNSNames: dnsnames,
		}
		csr, err := x509.CreateCertificateRequest(rand.Reader, req, key)
		if err != nil {
			panic(err)
		}
	*/

	/*
		crt, _, err := client.CreateCert(ctx, csr, 24*time.Hour, true)
		if err != nil {
			panic(err)
		}

		fmt.Println(crt)
	*/

	// TODO: Store cert key and crt ether as is, in DER format, or convert to PEM.

}

func createKeyFile(filename string) (*ecdsa.PrivateKey, error) {
	akey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}

	marshalledKey, err := x509.MarshalECPrivateKey(akey)
	if err != nil {
		return nil, err
	}

	pemPrivateBlock := &pem.Block{
		Type:  "ACME ACCOUNT ECDSA PRIVATE KEY",
		Bytes: marshalledKey,
	}

	pemPrivateFile, err := os.Create(filename)
	if err != nil {
		return nil, err
	}
	defer pemPrivateFile.Close()

	err = pem.Encode(pemPrivateFile, pemPrivateBlock)
	if err != nil {
		return nil, err
	}

	return akey, nil
}

func loadKeyFile(filename string) (*ecdsa.PrivateKey, error) {
	privateKeyFile, err := os.Open(filename)
	if err != nil {
		return nil, err
	}

	pemfileinfo, _ := privateKeyFile.Stat()
	var size int64 = pemfileinfo.Size()
	pembytes := make([]byte, size)
	buffer := bufio.NewReader(privateKeyFile)
	_, err = buffer.Read(pembytes)
	data, _ := pem.Decode([]byte(pembytes))
	privateKeyFile.Close()

	privateKeyImported, err := x509.ParseECPrivateKey(data.Bytes)
	return privateKeyImported, err
}
