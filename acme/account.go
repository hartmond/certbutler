package acme

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"fmt"
	"sort"

	"felix-hartmond.de/projects/certbutler/common"
	log "github.com/sirupsen/logrus"
	"golang.org/x/crypto/acme"
)

func newClient(akey *ecdsa.PrivateKey, acmeDirectory string) *acme.Client {
	return &acme.Client{
		Key:          akey,
		DirectoryURL: acmeDirectory,
		UserAgent:    "CertButler/v0.2-dev",
	}
}

func loadAccount(ctx context.Context, accountFile string, acmeDirectory string) (*acme.Client, *acme.Account, error) {
	akey, err := common.LoadKeyFromPEMFile(accountFile, 0)
	if err != nil {
		return nil, nil, err
	}

	client := newClient(akey, acmeDirectory)
	account, err := client.GetReg(ctx, "")

	if account.Status != "valid" {
		log.Warnf("ACME login failed. Status of Account %s is %s", account.URI, account.Status)
		return nil, nil, fmt.Errorf("acme login failed. Account status is %s", account.Status)
	} else {
		log.Infof("Successfully logged in as %s", account.URI)
	}

	return client, account, err
}

func TestAccount(accountFile string, acmeDirectory string) {
	log.Info("Trying to login with account from config file")

	ctx := context.Background()

	_, account, err := loadAccount(ctx, accountFile, acmeDirectory)
	if err != nil {
		log.Errorf("ACME login failed. Could not get Registration info: %s", err)
		return
	}

	if account.Status != acme.StatusValid {
		log.Errorf("ACME login failed. Status of Account %s is %s", account.URI, account.Status)
		return
	}

	log.Infof("Current contact addresses are: %s", account.Contact)
	log.Infof("Current account status is: %s", account.Status)
}

func RegisterAccount(ctx context.Context, accountFile string, acmeDirectory string, mailContacts []string, acceptTOS bool) (*acme.Client, error) {
	log.Info("Starting registration of acme account")

	// TODO check if account file already exists (force overwrite paramter)
	// TODO check if account file can be written (file permissions; maybe by creating handle here)

	akey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}

	var tosURL string
	contacts := []string{}
	for _, mail := range mailContacts {
		contacts = append(contacts, "mailto:"+mail)
	}
	client := newClient(akey, acmeDirectory)
	account, err := client.Register(ctx, &acme.Account{Contact: contacts}, func(url string) bool {
		tosURL = url
		log.Infof("Terms of Service of ACME endpoint: %s", tosURL)
		if acceptTOS {
			log.Info("Accepting TOS as specified in paramter or config file")
			return true
		}
		return false // TODO IMPLEMENT INTERACTIVE INPUT
	})
	if err != nil {
		return nil, err
	}

	if account.Status != "valid" {
		log.Warnf("ACME registration failed failed. Retruned Account URI %s and Status %s", account.URI, account.Status)
	} else {
		log.Infof("Successfully registered account. Account id is %s", account.URI)
	}

	err = common.SaveToPEMFile(accountFile, akey, nil, fmt.Sprintf("ACME Account URI: %s\nAccepted TOS: %s\nContact addresses: %s", account.URI, tosURL, mailContacts))
	if err != nil {
		return nil, err
	}
	return client, nil
}

func UpdateAccount(accountFile string, acmeDirectory string, mailContacts []string) {
	log.Info("Login to change contact addresses")

	ctx := context.Background()

	client, account, err := loadAccount(ctx, accountFile, acmeDirectory)
	if err != nil {
		log.Errorf("ACME login failed: %s", err)
		return
	}

	newContacts := []string{}
	for _, mail := range mailContacts {
		newContacts = append(newContacts, "mailto:"+mail)
	}

	if compareContacts(account.Contact, newContacts) {
		log.Info("No change in contact addesses ... aborting")
		return
	}
	log.Infof("Old contact addresses are: %s", account.Contact)

	account.Contact = newContacts
	account, err = client.UpdateReg(ctx, account)
	if err != nil {
		log.Error("Update of contact addresses failed: %s", err)
		return
	}
	log.Infof("Updated contact addresses to: %s", account.Contact)
}

func compareContacts(oldContacts, newContacts []string) bool {
	if len(oldContacts) != len(newContacts) {
		return false
	}

	sort.Strings(oldContacts)
	sort.Strings(newContacts)

	for i, v := range oldContacts {
		if v != newContacts[i] {
			return false
		}
	}
	return true
}
