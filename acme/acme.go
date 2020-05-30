package acme

import (
	"bufio"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"fmt"
	"os"

	"crypto/x509"
	"encoding/pem"

	"golang.org/x/crypto/acme"
)

func loadAccount(ctx context.Context, accountFile string, acmeDirectory string) (*acme.Client, error) {
	akey, err := loadKeyFile(accountFile)
	if err != nil {
		return nil, err
	}

	client := &acme.Client{Key: akey, DirectoryURL: acmeDirectory}
	_, err = client.GetReg(ctx, "")

	return client, err
}

func registerAccount(ctx context.Context, accountFile string, acmeDirectory string) (*acme.Client, error) {
	akey, err := createAcmeAccountFile(accountFile)
	if err != nil {
		return nil, err
	}

	client := &acme.Client{Key: akey, DirectoryURL: acmeDirectory}
	_, err = client.Register(ctx, &acme.Account{}, acme.AcceptTOS)

	return client, err
}

func RequestCertificate(dnsNames []string, accountFile string, certFileBase string, mustStaple bool, acmeDirectory string, registerIfMissing bool) error {
	ctx := context.Background()
	var client *acme.Client
	var err error

	client, err = loadAccount(ctx, accountFile, acmeDirectory)
	if err != nil {
		if !registerIfMissing {
			return err
		}
		client, err = registerAccount(ctx, accountFile, acmeDirectory)
		if err != nil {
			return err
		}
	}

	fmt.Println("Sending AuthorizeOrder Request")

	order, err := client.AuthorizeOrder(ctx, acme.DomainIDs(dnsNames...))
	if err != nil {
		return err
	}

	fmt.Println("Autorizing Domains")

	pendigChallenges := []*acme.Challenge{}
	dnsTokens := []string{}

	for _, authURL := range order.AuthzURLs {
		authz, err := client.GetAuthorization(ctx, authURL)
		if err != nil {
			return err
		}

		if authz.Status == acme.StatusValid {
			fmt.Println(authz.Identifier.Value + " alredy autorized")
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
			return fmt.Errorf("no dns-01 challenge for %q", authURL)
		}

		val, err := client.DNS01ChallengeRecord(chal.Token)
		if err != nil {
			return fmt.Errorf("dns-01 token for %q: %v", authz.Identifier, err)
		}

		fmt.Printf("hosting dns challenge for %s: %s\n", authz.Identifier, val)

		dnsTokens = append(dnsTokens, val)
		pendigChallenges = append(pendigChallenges, chal)
	}

	if len(pendigChallenges) > 0 {
		// Preparing authorizsations - Start DNS server
		closeServer := hostDNS(dnsTokens)

		fmt.Println("Accepting pendig challanges")
		for _, chal := range pendigChallenges {
			if _, err := client.Accept(ctx, chal); err != nil {
				return fmt.Errorf("dns-01 accept for %q: %v", chal, err)
			}
		}

		fmt.Println("Waiting for authorizations...")
		for _, authURL := range order.AuthzURLs {
			if _, err := client.WaitAuthorization(ctx, authURL); err != nil {
				return fmt.Errorf("authorization for %q failed: %v", authURL, err)
			}
		}

		// Authorizations done - Stop DNS server
		closeServer <- true
	}

	fmt.Println("Generating PrivateKey and CSR")

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return err
	}

	keyBytes, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return err
	}
	savePEM("PRIVATE KEY", certFileBase+".pem", keyBytes, false)
	if err != nil {
		return err
	}

	// TODO add must staple if requested
	req := &x509.CertificateRequest{
		DNSNames: dnsNames,
	}
	csr, err := x509.CreateCertificateRequest(rand.Reader, req, key)
	if err != nil {
		return err
	}

	fmt.Println("Requesting Certificate")

	crt, _, err := client.CreateOrderCert(ctx, order.FinalizeURL, csr, true)
	if err != nil {
		return err
	}

	savePEM("CERTIFICATE", certFileBase+".pem", crt[0], true)
	if err != nil {
		return err
	}

	first := true
	for _, cert := range crt[1:] {
		savePEM("CERTIFICATE", certFileBase+".pem.issue", cert, !first)
		if err != nil {
			return err
		}
		first = false
	}

	return nil
}

func savePEM(dataType, filename string, data []byte, append bool) error {
	flags := os.O_CREATE | os.O_WRONLY
	if append {
		flags |= os.O_APPEND
	} else {
		flags |= os.O_TRUNC
		// TODO if file exists; rename old file to archive it
	}
	file, err := os.OpenFile(filename, flags, 0600)
	if err != nil {
		return err
	}
	defer file.Close()

	pemBlock := &pem.Block{
		Type:  dataType,
		Bytes: data,
	}
	err = pem.Encode(file, pemBlock)
	if err != nil {
		return err

	}
	return nil
}

func createAcmeAccountFile(filename string) (*ecdsa.PrivateKey, error) {
	akey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}

	marshalledKey, err := x509.MarshalECPrivateKey(akey)
	if err != nil {
		return nil, err
	}

	savePEM("ACME ACCOUNT PRIVATE KEY", filename, marshalledKey, false)
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
