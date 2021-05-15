package cmd

import (
	log "github.com/sirupsen/logrus"

	"felix-hartmond.de/projects/certbutler/common"
	"felix-hartmond.de/projects/certbutler/scheduler"
	"github.com/spf13/cobra"
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
		configs := []common.Config{}
		for _, filename := range configFiles {
			log.Printf("Parsing config: %s", filename)
			config, err := common.LoadConfig(filename)
			if err != nil {
				log.Errorf("Could not parse config file %s: %s", filename, err)
				return
			}
			configs = append(configs, config)
		}

		scheduler.RunConfig(configs, oneShot)
	},
}
