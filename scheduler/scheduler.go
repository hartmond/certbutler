package scheduler

import (
	"sync"
	"time"

	"felix-hartmond.de/projects/certbutler/acme"
	"felix-hartmond.de/projects/certbutler/ocsp"
)

type ConfigSet []Config

type Config struct {
	CertFile string

	DnsNames        []string
	MustStaple      bool
	AcmeDirectory   string
	AcmeAccountFile string
	RegsiterAcme    bool

	UpdateCert bool
	UpdateOCSP bool

	RunInteralMinutes int
}

// RunConfig starts cerbutler tasked based on a configuration
func RunConfig(configSet ConfigSet) {
	wg := &sync.WaitGroup{}

	for _, config := range configSet {
		if config.RunInteralMinutes == 0 {
			wg.Add(1)
			go func() {
				process(config)
				wg.Done()
			}()
		} else {
			ticker := time.NewTicker(time.Duration(config.RunInteralMinutes) * time.Minute)
			wg.Add(1) // this will never be set to done -> runs indefinitely
			go func(waitChannel <-chan time.Time, config Config) {
				for {
					process(config)
					<-waitChannel
				}
			}(ticker.C, config)
		}
	}
	wg.Wait()
}

func process(config Config) {
	// TODO real check of certificate + ocsp fiele
	// run required steps dependent on certificate/ocsp file status and configuration

	// cert request without prior check for deveoplment - TODO remove
	err := acme.RequestCertificate(config.DnsNames, config.AcmeAccountFile, config.CertFile, config.MustStaple, config.AcmeDirectory, config.RegsiterAcme)
	if err != nil {
		// request failed - TODO handle
		panic(err)
	}

	// ocsp request without prior check for deveoplment - TODO remove
	ocspResponse, err := ocsp.GetOcspResponse(config.CertFile)
	if err != nil {
		panic(err)
	}
	ocsp.PrintStatus(ocspResponse)

}
