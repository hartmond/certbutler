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

	renewCert := checkCertRenew(config)

	if renewCert {
		certs, key, err := acme.RequestCertificate(config.DnsNames, config.AcmeAccountFile, config.MustStaple, config.AcmeDirectory, config.RegsiterAcme)
		if err != nil {
			log.Fatalf("Requesting certificate for %s failed with error %s", common.FlattenStringSlice(config.DnsNames), err.Error())
			// request failed - TODO handle
			panic(err)
		}

		if config.Mode == "nginx" {
			err = nginx.SaveCert(config, certs, key)
			if err != nil {
				panic(err) // TODO
			}
			err = nginx.ReloadServer(config)
			if err != nil {
				panic(err) // TODO
			}
		} else {
			err = haproxy.SaveCert(config, certs, key)
			if err != nil {
				panic(err) // TODO
			}
			err = haproxy.UpdateServer(config, certs, key)
			if err != nil {
				panic(err) // TODO
			}
		}
	}

	if config.Mode == "haproxy" && (renewCert || checkOCSPRenew(config)) {
		ocspResponse, err := ocsp.GetOcspResponse(config.CertFile)
		if err != nil {
			panic(err)
		}

		err = haproxy.SaveOCSP(config, ocspResponse)
		if err != nil {
			panic(err) // TODO
		}
		err = haproxy.UpdateOCSP(config, ocspResponse)
		if err != nil {
			panic(err) // TODO
		}
	}
}

func checkCertRenew(config common.Config) bool {
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
	ocsp, err := ocsp.LoadFromFile(config.CertFile)
	if err != nil {
		// ocsp missing or not valid => renew ocsp
		return true
	}

	if remainingValidity := time.Until(ocsp.NextUpdate); remainingValidity < time.Duration(3*24)*time.Hour {
		// ocsp expires soon (in 3 days) => renew ocsp
		return true
	}

	return false
}
