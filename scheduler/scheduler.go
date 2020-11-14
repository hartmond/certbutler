package scheduler

import (
	"sync"
	"time"

	log "github.com/sirupsen/logrus"

	"felix-hartmond.de/projects/certbutler/acme"
	"felix-hartmond.de/projects/certbutler/common"
	"felix-hartmond.de/projects/certbutler/ocsp"
	"felix-hartmond.de/projects/certbutler/webserver"
)

// RunConfig starts cerbutler tasked based on a configuration
func RunConfig(configs []common.Config) {
	wg := &sync.WaitGroup{}

	for _, config := range configs {
		c := config
		if config.RunIntervalMinutes == 0 {
			wg.Add(1)
			go func() {
				process(c)
				wg.Done()
			}()
		} else {
			ticker := time.NewTicker(time.Duration(config.RunIntervalMinutes) * time.Minute)
			wg.Add(1) // this will never be set to done -> runs indefinitely
			go func(waitChannel <-chan time.Time, config common.Config) {
				for {
					process(c)
					<-waitChannel
				}
			}(ticker.C, config)
		}
	}
	wg.Wait()
}

func process(config common.Config) {
	log.Println("Starting Run")

	webServer := webserver.New(config)

	// check tasks for this run
	handleCert, handleOCSP := webServer.GetRequirements()               // which parts should certbutler handle
	needCert := handleCert && acme.CheckCertRenew(config)               // has the certificate to be renewed?
	needOCSP := handleOCSP && (needCert || ocsp.CheckOCSPRenew(config)) // has ocsp to be renewed?

	if needCert {
		log.Println("Certificate needs renewal")
		certs, key, err := acme.RequestCertificate(config.DNSNames, config.AcmeAccountFile, config.MustStaple, config.AcmeDirectory, config.RegsiterAcme)
		if err != nil {
			log.Fatalf("Requesting certificate for %s failed with error %s", common.FlattenStringSlice(config.DNSNames), err.Error())
		}

		err = webServer.SetCert(certs, key)
		if err != nil {
			log.Fatalf("Writing ceritifcate to disk failed with error %s", err.Error())
		}
		log.Println("Certificate renewed successfully")
	} else {
		log.Println("Certificate still valid, not renewing")
	}

	if needOCSP {
		log.Println("OCSP response needs renewal")
		ocspResponse, err := ocsp.GetOCSPResponse(config.CertFile)
		if err != nil {
			log.Fatalf("Requesting new OCSP response for %s failed with error %s", common.FlattenStringSlice(config.DNSNames), err.Error())
		}

		err = webServer.SetOCSP(ocspResponse)
		if err != nil {
			log.Fatalf("Writing OCSP response to disk failed with error %s", err.Error())
		}
		log.Println("OCSP response renewed successfully")
	} else {
		if handleOCSP {
			log.Println("OCSP response still valid, not renewing")
		}
	}

	if needCert || needOCSP {
		if config.UpdateServer {
			log.Println("Reloading web server config due to changes")
			err := webServer.UpdateServer()
			if err != nil {
				log.Fatalf("Error updating web server: %s", err.Error())
			}
		}
	} else {
		log.Println("No changes, not reloading the web server config")
	}
}
