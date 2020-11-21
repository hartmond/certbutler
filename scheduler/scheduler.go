package scheduler

import (
	"io/ioutil"
	"os"
	"sync"
	"time"

	log "github.com/sirupsen/logrus"

	"felix-hartmond.de/projects/certbutler/acme"
	"felix-hartmond.de/projects/certbutler/common"
	"felix-hartmond.de/projects/certbutler/ocsp"
	"felix-hartmond.de/projects/certbutler/postprocessing"
)

// RunConfig starts cerbutler tasked based on a configuration
func RunConfig(configs []common.Config) {
	wg := &sync.WaitGroup{}

	for _, config := range configs {
		c := config

		if config.HaProxy.HAProxySocket != "" && !config.Files.SingleFile {
			log.Warn("HaProxy post-processor is enabled but certificate and key are stored in two files. This combination usually does not work.")
		}

		if config.Nginx.ReloadNginx && config.Files.SingleFile {
			log.Warn("Nginx post-processor is enabled but certificate and key are stored in one combined file. This combination usually does not work.")
		}

		if config.Timing.RunIntervalMinutes == 0 {
			wg.Add(1)
			go func() {
				process(c)
				wg.Done()
			}()
		} else {
			ticker := time.NewTicker(time.Duration(config.Timing.RunIntervalMinutes) * time.Minute)
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
	log.Info("Starting Run")

	updateResultData := common.UpdateResultData{}

	// check tasks for this run
	needCert := config.Timing.RenewalDueCert > 0 && acme.CheckCertRenew(config.Files.CertFile, config.Timing.RenewalDueCert)               // has the certificate to be renewed?
	needOCSP := config.Timing.RenewalDueOCSP > 0 && (needCert || ocsp.CheckOCSPRenew(config.Files.CertFile, config.Timing.RenewalDueOCSP)) // has ocsp to be renewed?

	if needCert {
		log.Info("Certificate needs renewal")

		// Request certificate
		certs, key, err := acme.RequestCertificate(config.Certificate)
		if err != nil {
			log.Warnf("Requesting certificate for %s failed with error %s", common.FlattenStringSlice(config.Certificate.DNSNames), err.Error())
		} else {
			// Write Certificate to file
			err = common.WriteCertToFile(certs, key, config.Files.CertFile, config.Files.KeyFile, config.Files.SingleFile)
			if err != nil {
				log.Fatalf("Writing ceritifcate to disk failed with error %s", err.Error())
			}
			log.Info("Certificate renewed and stored to file successfully")

			// Stage Certificate for updates
			updateResultData.Certificates = certs
			updateResultData.Key = key
		}
	} else {
		if config.Timing.RenewalDueCert > 0 {
			log.Info("Certificate still valid, not renewing")
		}
	}

	if needOCSP {
		log.Info("OCSP response needs renewal")
		ocspResponse, err := ocsp.GetOCSPResponse(config.Files.CertFile)
		if err != nil {
			log.Warnf("Requesting new OCSP response for %s failed with error %s", common.FlattenStringSlice(config.Certificate.DNSNames), err.Error())
		} else {

			// Store OCSP response in file
			err = ioutil.WriteFile(config.Files.CertFile+".ocsp", ocspResponse, os.FileMode(int(0600)))
			if err != nil {
				log.Fatalf("Writing OCSP response to disk failed with error %s", err.Error())
			}
			log.Info("OCSP response renewed successfully")

			// Stage ocsp response for updates
			updateResultData.OCSPResponse = ocspResponse
		}
	} else {
		if config.Timing.RenewalDueOCSP > 0 {
			log.Info("OCSP response still valid, not renewing")
		}
	}

	if needCert || needOCSP {
		if config.HaProxy.HAProxySocket != "" {
			err := postprocessing.ProcessHaProxy(config.HaProxy, config.Files, updateResultData)
			if err != nil {
				log.Fatalf("Error updating haproxy: %s", err.Error())
			}
		}

		if config.Nginx.ReloadNginx {
			err := postprocessing.ProcessNginx()
			if err != nil {
				log.Fatalf("Error updating nginx: %s", err.Error())
			}
		}

		if config.DeployHook.Executable != "" {
			err := postprocessing.ProcessDeployHook(config.DeployHook)
			if err != nil {
				log.Fatalf("Error updating nginx: %s", err.Error())
			}
		}
	} else {
		log.Info("No changes, nothing to process")
	}
}
