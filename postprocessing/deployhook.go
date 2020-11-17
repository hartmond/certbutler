package postprocessing

import (
	"os/exec"

	log "github.com/sirupsen/logrus"

	"felix-hartmond.de/projects/certbutler/common"
)

// ProcessDeployHook runs the defined deploy hook executable
func ProcessDeployHook(config common.DeployHookConfiguration) error {
	err := exec.Command(config.Executable).Run()
	if err != nil {
		return err
	}
	log.Info("Deploy hook executed successfully")
	return nil
}
