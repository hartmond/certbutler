package cmd

import (
	"fmt"
	"io/ioutil"
	"log"

	"felix-hartmond.de/projects/certbutler/common"
	"felix-hartmond.de/projects/certbutler/scheduler"
	"github.com/spf13/cobra"
	"gopkg.in/yaml.v3"
)

var (
	configFiles []string
	oneShot     bool
)

func init() {
	rootCmd.AddCommand(runCmd)

	runCmd.Flags().StringArrayVarP(&configFiles, "config", "c", []string{}, "List of config files to run")
	runCmd.MarkFlagRequired("config")

	runCmd.Flags().BoolVar(&oneShot, "oneshot", false, "Ignore timing configuration and run certbuler only once")
}

var runCmd = &cobra.Command{
	Use:   "run",
	Short: "Runs the certbutler",
	Long: `Runs the certbutler
	
Certbutler can handle multiple configurations simultaniouly.
Thereby, collisions of listening to the dns port of concurrent runs cannot happen.
To run multiple configurations, provide the config paramter multiple times.
(e.g. certbutler run -c a.yaml -c b.yaml`,
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Printf("run command configs:%s oneshot:%t\n", configFiles, oneShot)

		configs := []common.Config{}
		for _, filename := range configFiles {
			log.Printf("Parsing config: %s", filename)
			yamlBytes, err := ioutil.ReadFile(filename)
			if err != nil {
				panic(err)
			}

			var config common.Config
			err = yaml.Unmarshal(yamlBytes, &config)
			if err != nil {
				panic(err)
			}
			configs = append(configs, config)
		}

		scheduler.RunConfig(configs)
	},
}
