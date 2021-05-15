package acme

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"fmt"
	"time"

	log "github.com/sirupsen/logrus"

	"felix-hartmond.de/projects/certbutler/common"
	"golang.org/x/crypto/acme"
)

// RequestCertificate runs the acme flow to request a certificate with the desired contents
func RequestCertificate(certificateConfig common.CertificateConfiguration) ([][]byte, *ecdsa.PrivateKey, error) {
	ctx := context.Background()
	var client *acme.Client
	var err error

	client, _, err = loadAccount(ctx, certificateConfig.AcmeAccountFile, certificateConfig.AcmeDirectory)
	if err != nil {
		if !certificateConfig.RegisterAcme {
			return nil, nil, err
		}
		client, err = RegisterAccount(ctx, certificateConfig.AcmeAccountFile, certificateConfig.AcmeDirectory, certificateConfig.AcmeMailContacts, certificateConfig.AcceptAcmeTOS)
		if err != nil {
			return nil, nil, err
		}
	}

	log.Println("Sending AuthorizeOrder Request")

	order, err := client.AuthorizeOrder(ctx, acme.DomainIDs(certificateConfig.DNSNames...))
	if err != nil {
		return nil, nil, err
	}

	log.Println("Authorizing domains")

	pendigChallenges := []*acme.Challenge{}
	dnsTokens := []string{}

	for _, authURL := range order.AuthzURLs {
		authz, err := client.GetAuthorization(ctx, authURL)
		if err != nil {
			return nil, nil, err
		}

		if authz.Status == acme.StatusValid {
			log.Println(authz.Identifier.Value + " already authorized")
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
			return nil, nil, fmt.Errorf("no dns-01 challenge for %q", authURL)
		}

		val, err := client.DNS01ChallengeRecord(chal.Token)
		if err != nil {
			return nil, nil, fmt.Errorf("dns-01 token for %q: %v", authz.Identifier, err)
		}

		log.Printf("Hosting dns challenge for %s: %s\n", authz.Identifier, val)

		dnsTokens = append(dnsTokens, val)
		pendigChallenges = append(pendigChallenges, chal)
	}

	if len(pendigChallenges) > 0 {
		// Preparing authorizations - Start DNS server
		closeServer := hostDNS(dnsTokens)

		log.Println("Accepting pending challenges")
		for _, chal := range pendigChallenges {
			if _, err := client.Accept(ctx, chal); err != nil {
				return nil, nil, fmt.Errorf("dns-01 accept for %q: %v", chal, err)
			}
		}

		log.Println("Waiting for authorizations...")
		for _, authURL := range order.AuthzURLs {
			if _, err := client.WaitAuthorization(ctx, authURL); err != nil {
				return nil, nil, fmt.Errorf("authorization for %q failed: %v", authURL, err)
			}
		}

		// Authorizations done - Stop DNS server
		closeServer <- true
	}

	log.Println("Generating PrivateKey and CSR")

	var curve elliptic.Curve
	switch certificateConfig.EllipticCurve {
	case "":
		fallthrough
	case "P384":
		curve = elliptic.P384()
	case "P256":
		curve = elliptic.P256()
	default:
		return nil, nil, fmt.Errorf("invalid EC Curve in configuration: %s, possible values are P256 and P384", certificateConfig.EllipticCurve)
	}
	key, err := ecdsa.GenerateKey(curve, rand.Reader)
	if err != nil {
		return nil, nil, err
	}

	req := &x509.CertificateRequest{
		DNSNames: certificateConfig.DNSNames,
	}

	if certificateConfig.MustStaple {
		req.ExtraExtensions = append(req.ExtraExtensions, pkix.Extension{
			Id:    asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 1, 24},
			Value: []byte{0x30, 0x03, 0x02, 0x01, 0x05},
		})
	}

	csr, err := x509.CreateCertificateRequest(rand.Reader, req, key)
	if err != nil {
		return nil, nil, err
	}

	log.Println("Requesting certificate")

	crts, _, err := client.CreateOrderCert(ctx, order.FinalizeURL, csr, true)
	if err != nil {
		return nil, nil, err
	}

	return crts, key, nil
}

// CheckCertRenew checks if the stored certificate exists and is still longer valid than renewalduecert from config
func CheckCertRenew(certFile string, renewalDueCert int) bool {
	cert, err := common.LoadCertFromPEMFile(certFile, 0)
	if err != nil {
		// no or invalid certificate => request cert
		return true
	}

	if remainingValidity := time.Until(cert.NotAfter); remainingValidity < time.Duration(renewalDueCert*24)*time.Hour {
		return true
	}

	return false
}