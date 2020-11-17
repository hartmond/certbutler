package postprocessing

import (
	"os/exec"

	"felix-hartmond.de/projects/certbutler/common"
)

// ProcessDeployHook runs the defined deploy hook executable
func ProcessDeployHook(config common.DeployHookConfiguration) error {
	return exec.Command(config.Executable).Run()
}
