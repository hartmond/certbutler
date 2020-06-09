package scheduler

import (
	"log"
	"sync"
	"time"

	"felix-hartmond.de/projects/certbutler/acme"
	"felix-hartmond.de/projects/certbutler/common"
	"felix-hartmond.de/projects/certbutler/haproxy"
	"felix-hartmond.de/projects/certbutler/nginx"
	"felix-hartmond.de/projects/certbutler/ocsp"
)

// RunConfig starts cerbutler tasked based on a configuration
func RunConfig(configs []common.Config) {
	wg := &sync.WaitGroup{}

	for _, config := range configs {
		if config.RunIntervalMinutes == 0 {
			wg.Add(1)
			go func() {
				process(config)
				wg.Done()
			}()
		} else {
			ticker := time.NewTicker(time.Duration(config.RunIntervalMinutes) * time.Minute)
			wg.Add(1) // this will never be set to done -> runs indefinitely
			go func(waitChannel <-chan time.Time, config common.Config) {
				for {
					process(config)
					<-waitChannel
				}
			}(ticker.C, config)
		}
	}
	wg.Wait()
}

func process(config common.Config) {
	log.Println("Starting Run")

	var webServer common.WebServerInteraction
	if config.Mode == "haproxy" {
		webServer = haproxy.New(config)
	} else if config.Mode == "nginx" {
		webServer = nginx.New(config)
	} else {
		log.Fatalf("Web server type %s not supported")
	}

	// check tasks for this run
	handleCert, handleOCSP := webServer.GetRequirements()               // which parts should certbutler handle
	needCert := handleCert && acme.CheckCertRenew(config)               // has the certificate to be renewed?
	needOCSP := handleOCSP && (needCert || ocsp.CheckOCSPRenew(config)) // has ocsp to be renewed?

	if needCert {
		certs, key, err := acme.RequestCertificate(config.DnsNames, config.AcmeAccountFile, config.MustStaple, config.AcmeDirectory, config.RegsiterAcme)
		if err != nil {
			log.Fatalf("Requesting certificate for %s failed with error %s", common.FlattenStringSlice(config.DnsNames), err.Error())
			// request failed - TODO handle
			panic(err)
		}

		webServer.SetCert(certs, key)
	}

	if needOCSP {
		ocspResponse, err := ocsp.GetOcspResponse(config.CertFile)
		if err != nil {
			panic(err) // TODO
		}

		webServer.SetOCSP(ocspResponse)
	}

	// UpdateServer takes track internally if something has to be done here
	err := webServer.UpdateServer()
	if err != nil {
		panic(err) // TODO
	}
}
