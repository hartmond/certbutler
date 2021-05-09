package acme

import (
	"context"

	"felix-hartmond.de/projects/certbutler/common"
	log "github.com/sirupsen/logrus"
)

func TestAccount(accountFile string, acmeDirectory string) {
	log.Info("Trying to login with account from config file")

	ctx := context.Background()

	akey, err := common.LoadKeyFromPEMFile(accountFile, 0)
	if err != nil {
		log.Errorf("Key file could not be loaded: %s", err)
		return
	}

	client := newClient(akey, acmeDirectory)
	account, err := client.GetReg(ctx, "")
	if err != nil {
		log.Errorf("ACME login failed. Could note get Registration info: %s", err)
	}

	if account.Status != "valid" {
		log.Errorf("ACME login failed. Status of Account %s is %s", account.URI, account.Status)
		return
	}

	log.Infof("Successfully logged in as %s", account.URI)
	log.Infof("Current contact addresses are: %s", account.Contact)
	log.Infof("Current account status is: %s", account.Status)
}
