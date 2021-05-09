package cmd

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

var configFile string
var acceptTOS bool
var overwriteFile bool

func init() {
	rootCmd.AddCommand(accountCmd)

	accountCmd.AddCommand(registerCmd)

	registerCmd.Flags().StringVarP(&configFile, "config", "c", "", "File containing the configuration for the accout")
	registerCmd.MarkFlagRequired("config")
	registerCmd.Flags().BoolVar(&acceptTOS, "accept-tos", false, "Automatically accept the server's terms of service")
	registerCmd.Flags().BoolVar(&overwriteFile, "force-overwrite-file", false, "Overwrite an existing account key file")

	accountCmd.AddCommand(testCmd)
	testCmd.Flags().StringVarP(&configFile, "config", "c", "", "File containing the configuration for the accout")
	testCmd.MarkFlagRequired("config")

	accountCmd.AddCommand(updateCmd)
	updateCmd.Flags().StringVarP(&configFile, "config", "c", "", "File containing the configuration for the accout")
	updateCmd.MarkFlagRequired("config")
}

var accountCmd = &cobra.Command{
	Use:   "account",
	Short: "Functions to manage the account at the ACME provider",
	Long:  `Functions to manage the account at the ACME provider`,
	Run: func(cmd *cobra.Command, args []string) {
		cmd.Help()
		os.Exit(1)
	},
}

var registerCmd = &cobra.Command{
	Use:   "register",
	Short: "Register an account at the ACME provider",
	Long: `Register a new account at the ACME provider

Account details is taken from the acmeaccount section of a config file.
Acceptance of the server's terms of service can be given interactively or via command line flag.
The command will abort if the account file already exists (unless forced).`,
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Printf("account register command config:%s tos:%t overwrite:%t\n", configFile, acceptTOS, overwriteFile)
	},
}

var testCmd = &cobra.Command{
	Use:   "test",
	Short: "Tests the login at the ACME provider",
	Long: `Tests the login at the ACME provider

This command tries to login at the ACME provider and prints all details about the ACME account.
It can be used to test the configuration without issuring a certificate.`,
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Printf("account test command config:%s\n", configFile)
	},
}

var updateCmd = &cobra.Command{
	Use:   "update",
	Short: "Updates the contact addresses of an account",
	Long: `Updates the contact addresses of an account

Account configuration is taken from the acmeaccount section of a config file.
The command will update the contact addresses and print all info about the account afterwards.`,
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Printf("account update command config:%s\n", configFile)
	},
}
