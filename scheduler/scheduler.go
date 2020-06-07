package scheduler

import (
	"log"
	"sync"
	"time"

	"felix-hartmond.de/projects/certbutler/acme"
	"felix-hartmond.de/projects/certbutler/common"
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
	renewCert, renewOCSP := getOpenTasks(config)

	log.Printf("Starting run (cert: %t ocsp: %t)\n", renewCert, renewOCSP)

	if config.UpdateCert && renewCert {
		err := acme.RequestCertificate(config.DnsNames, config.AcmeAccountFile, config.CertFile, config.MustStaple, config.AcmeDirectory, config.RegsiterAcme)
		if err != nil {
			log.Fatalf("Requesting certificate for %s failed with error %s", common.FlattenStringSlice(config.DnsNames), err.Error())
			// request failed - TODO handle
			panic(err)
		}
	}

	if config.UpdateOCSP && renewOCSP {
		ocspResponse, err := ocsp.GetOcspResponse(config.CertFile)
		if err != nil {
			panic(err)
		}
		ocsp.PrintStatus(ocspResponse)
	}

	if config.HAProxySocket != "" {
		// TODO make cert, key, ocspResponse available for calling
		if renewCert && renewOCSP {
			// TODO haproxy.UpdateHAProxy(config.HAProxySocket, cert, key, ocspResponse)
		} else if renewCert {
			// TODO haproxy.UpdateHAProxy(config.HAProxySocket, cert, key, nil)
		} else if renewOCSP {
			// TODO haproxy.UpdateHAProxy(config.HAProxySocket, nil, nil, ocspResponse)
		}
	}
}

func getOpenTasks(config common.Config) (renewCert, renewOCSP bool) {
	if checkCertRenew(config) {
		log.Printf("Certificate is due to renewal for %s", common.FlattenStringSlice(config.DnsNames))
		return true, config.UpdateOCSP
	}

	if checkOCSPRenew(config) {
		return false, true
	}

	// everythings fine => nothing to do
	return false, false
}

func checkCertRenew(config common.Config) bool {
	if !config.UpdateCert {
		return false
	}

	cert, err := common.LoadCertFromPEMFile(config.CertFile, 0)
	if err != nil {
		// no or invalid certificate => request cert
		return true
	}

	if remainingValidity := time.Until(cert.NotAfter); remainingValidity < time.Duration(config.RenewalDue)*time.Hour {
		return true
	}

	return false
}

func checkOCSPRenew(config common.Config) bool {
	if !config.UpdateOCSP {
		return false
	}

	ocsp, err := ocsp.LoadFromFile(config.CertFile)
	if err != nil {
		// cert ok but ocsp missing or not valid => renew ocsp
		return true
	}

	if remainingValidity := time.Until(ocsp.NextUpdate); remainingValidity < time.Duration(3*24)*time.Hour {
		// cert ok but ocsp expires soon (in 3 days) => renew ocsp
		return true
	}

	return false
}
